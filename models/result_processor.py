import re
from typing import Dict, Any, List

from assemblyline_v4_service.common.result import (
    Result,
    ResultSection,
    ResultKeyValueSection,
    ResultTableSection,
    TableRow,
    BODY_FORMAT,
)
from assemblyline_v4_service.common.request import ServiceRequest

from models.wasm_parser import (
    MINING_NAMES, MINING_POOL_PATTERNS, EMBEDDED_CODE_PATTERNS,
    SMUGGLING_PATTERNS, SUSPICIOUS_IMPORTS, URL_RE, IP_RE,
)


class ResultProcessor:
    def __init__(self, result: Result, request: ServiceRequest, log):
        self.result = result
        self.request = request
        self.log = log

    def process(self, parsed: Dict[str, Any]) -> None:
        self._add_module_info(parsed)
        self._check_imports(parsed)
        self._check_exports(parsed)
        self._check_memory(parsed)
        self._check_crypto_ops(parsed)
        self._check_data_strings(parsed)
        self._check_custom_sections(parsed)

    def _add_module_info(self, parsed: Dict[str, Any]) -> None:
        info = ResultKeyValueSection("WASM Module Information")
        info.set_item("Version", parsed["version"])
        info.set_item("Sections", len(parsed["sections"]))
        info.set_item("Imports", len(parsed["imports"]))
        info.set_item("Exports", len(parsed["exports"]))
        info.set_item("Functions", parsed["code_stats"]["function_count"])
        info.set_item("Total Operations", parsed["code_stats"]["total_ops"])
        info.set_item("Crypto Operations", parsed["code_stats"]["crypto_ops"])
        total_data_strings = len(parsed["data_strings"])
        info.set_item("Data Section Strings", total_data_strings)
        self.result.add_section(info)

    def _check_imports(self, parsed: Dict[str, Any]) -> None:
        if not parsed["imports"]:
            return

        # Check for mining-related import names
        mining_imports = []
        suspicious_imports = []

        for imp in parsed["imports"]:
            full_name = f"{imp['module']}.{imp['field']}"
            name_lower = full_name.lower()

            for mining_name in MINING_NAMES:
                if mining_name in name_lower:
                    mining_imports.append(full_name)
                    break

            for susp_name in SUSPICIOUS_IMPORTS:
                if susp_name.lower() in name_lower:
                    suspicious_imports.append(full_name)
                    break

        if mining_imports:
            section = ResultSection("Cryptomining Function Imports", body_format=BODY_FORMAT.TEXT)
            section.set_heuristic(1)
            for name in mining_imports:
                section.add_line(f"- {name}")
                section.heuristic.add_signature_id(name)
            self.result.add_section(section)

        if suspicious_imports:
            section = ResultSection("Suspicious Imports", body_format=BODY_FORMAT.TEXT)
            section.set_heuristic(5)
            for name in suspicious_imports:
                section.add_line(f"- {name}")
                section.heuristic.add_signature_id(name)
            self.result.add_section(section)

        # Add import listing
        if len(parsed["imports"]) <= 100:
            imp_section = ResultTableSection("Import Table")
            for imp in parsed["imports"]:
                imp_section.add_row(TableRow(
                    module=imp["module"],
                    field=imp["field"],
                ))
            self.result.add_section(imp_section)

    def _check_exports(self, parsed: Dict[str, Any]) -> None:
        if not parsed["exports"]:
            return

        mining_exports = []
        for exp in parsed["exports"]:
            name_lower = exp["name"].lower()
            for mining_name in MINING_NAMES:
                if mining_name in name_lower:
                    mining_exports.append(exp["name"])
                    break

        if mining_exports:
            section = ResultSection("Cryptomining Function Exports", body_format=BODY_FORMAT.TEXT)
            section.set_heuristic(1)
            for name in mining_exports:
                section.add_line(f"- {name}")
                section.heuristic.add_signature_id(name)
            self.result.add_section(section)

        if len(parsed["exports"]) <= 100:
            exp_section = ResultTableSection("Export Table")
            for exp in parsed["exports"]:
                kind_map = {0: "func", 1: "table", 2: "memory", 3: "global"}
                exp_section.add_row(TableRow(
                    name=exp["name"],
                    kind=kind_map.get(exp["kind"], str(exp["kind"])),
                    index=exp["index"],
                ))
            self.result.add_section(exp_section)

    def _check_memory(self, parsed: Dict[str, Any]) -> None:
        for mem in parsed["memory"]:
            initial = mem.get("initial_pages", 0)
            max_pages = mem.get("max_pages")
            # 256 pages = 16MB, typical threshold for mining scratchpads
            if initial > 256 or (max_pages and max_pages > 1024):
                section = ResultKeyValueSection("Excessive Memory Allocation")
                section.set_heuristic(7)
                section.set_item("Initial Pages", initial)
                section.set_item("Initial Size (MB)", initial * 64 // 1024)
                if max_pages:
                    section.set_item("Max Pages", max_pages)
                    section.set_item("Max Size (MB)", max_pages * 64 // 1024)
                self.result.add_section(section)

    def _check_crypto_ops(self, parsed: Dict[str, Any]) -> None:
        stats = parsed["code_stats"]
        total = stats["total_ops"]
        crypto = stats["crypto_ops"]
        if total == 0:
            return

        ratio = crypto / total
        # Flag if >5% of operations are crypto-related
        if ratio > 0.05 and crypto > 100:
            section = ResultKeyValueSection("Heavy Crypto Operations")
            section.set_heuristic(6)
            section.set_item("Crypto Operations", crypto)
            section.set_item("Total Operations", total)
            section.set_item("Ratio", f"{ratio:.1%}")
            self.result.add_section(section)

    def _check_data_strings(self, parsed: Dict[str, Any]) -> None:
        strings = parsed["data_strings"]
        if not strings:
            return

        all_strings = "\n".join(strings)

        # Check for mining pool addresses
        pool_hits = []
        for pattern in MINING_POOL_PATTERNS:
            for match in pattern.finditer(all_strings):
                # Get the full string containing the match
                for s in strings:
                    if match.group(0) in s:
                        pool_hits.append(s)
                        break

        if pool_hits:
            section = ResultSection("Mining Pool Addresses", body_format=BODY_FORMAT.TEXT)
            section.set_heuristic(3)
            seen = set()
            for hit in pool_hits[:20]:
                if hit not in seen:
                    section.add_line(f"- {hit[:200]}")
                    seen.add(hit)
            self.result.add_section(section)

        # Check for embedded JS/HTML
        embedded_hits = []
        for pattern in EMBEDDED_CODE_PATTERNS:
            for match in pattern.finditer(all_strings):
                embedded_hits.append(match.group(0))

        if embedded_hits:
            section = ResultSection("Embedded JavaScript/HTML in Data Section", body_format=BODY_FORMAT.TEXT)
            section.set_heuristic(2)
            seen = set()
            for hit in embedded_hits[:20]:
                clean = hit.strip()[:200]
                if clean not in seen:
                    section.add_line(f"- {clean}")
                    seen.add(clean)
            self.result.add_section(section)

        # Check for HTML smuggling
        smuggle_hits = []
        for pattern in SMUGGLING_PATTERNS:
            for match in pattern.finditer(all_strings):
                smuggle_hits.append(match.group(0))

        if smuggle_hits:
            section = ResultSection("HTML Smuggling Patterns", body_format=BODY_FORMAT.TEXT)
            section.set_heuristic(4)
            seen = set()
            for hit in smuggle_hits[:10]:
                if hit not in seen:
                    section.add_line(f"- {hit}")
                    seen.add(hit)
            self.result.add_section(section)

        # Extract URLs and IPs as IOCs
        urls = set()
        ips = set()
        for s in strings:
            for match in URL_RE.finditer(s):
                url = match.group(0).rstrip(".,;)'\"")
                if len(url) > 10:
                    urls.add(url)
            for match in IP_RE.finditer(s):
                ip = match.group(0)
                octets = ip.split(".")
                if all(0 <= int(o) <= 255 for o in octets):
                    if ip not in ("0.0.0.0", "127.0.0.1", "255.255.255.255"):
                        ips.add(ip)

        if urls or ips:
            section = ResultSection("Suspicious Data Section Strings", body_format=BODY_FORMAT.TEXT)
            section.set_heuristic(8)
            for url in sorted(urls)[:30]:
                section.add_line(url)
                section.add_tag("network.static.uri", url)
                domain_match = re.search(r"//([^/:?#\s]+)", url)
                if domain_match:
                    domain = domain_match.group(1)
                    if not re.match(r"^\d+\.\d+\.\d+\.\d+$", domain):
                        section.add_tag("network.static.domain", domain)
            for ip in sorted(ips)[:20]:
                section.add_line(f"IP: {ip}")
                section.add_tag("network.static.ip", ip)
            self.result.add_section(section)

    def _check_custom_sections(self, parsed: Dict[str, Any]) -> None:
        for custom in parsed["custom_sections"]:
            if not custom["strings"]:
                continue
            all_text = "\n".join(custom["strings"])
            # Check for embedded code in custom sections too
            has_code = any(p.search(all_text) for p in EMBEDDED_CODE_PATTERNS)
            if has_code:
                section = ResultSection(
                    f"Embedded Code in Custom Section: {custom['name']}",
                    body_format=BODY_FORMAT.TEXT,
                )
                section.set_heuristic(2)
                section.add_line(f"Section size: {custom['size']} bytes")
                self.result.add_section(section)
