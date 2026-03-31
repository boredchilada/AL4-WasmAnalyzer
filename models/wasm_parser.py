import re
import struct
from typing import Dict, List, Any, Optional

# WASM section IDs
SEC_CUSTOM = 0
SEC_TYPE = 1
SEC_IMPORT = 2
SEC_FUNCTION = 3
SEC_TABLE = 4
SEC_MEMORY = 5
SEC_GLOBAL = 6
SEC_EXPORT = 7
SEC_START = 8
SEC_ELEMENT = 9
SEC_CODE = 10
SEC_DATA = 11

# Crypto operation opcodes (i64/i32 XOR, shifts, rotates)
CRYPTO_OPS = {
    0x73,  # i32.xor
    0x74,  # i32.shl
    0x75,  # i32.shr_u
    0x76,  # i32.shr_s
    0x77,  # i32.rotl
    0x78,  # i32.rotr
    0x85,  # i64.xor
    0x86,  # i64.shl
    0x87,  # i64.shr_u
    0x88,  # i64.shr_s
    0x89,  # i64.rotl
    0x8a,  # i64.rotr
}

# Cryptomining related names
MINING_NAMES = [
    "cryptonight", "cn_slow_hash", "keccak", "blake", "groestl", "skein",
    "jh_hash", "aesenc", "aesdec", "hash_extra", "randomx", "rx_run",
    "argon2", "scrypt", "ethash", "equihash", "cuckoo",
]

# Mining pool patterns
MINING_POOL_PATTERNS = [
    re.compile(r"stratum\+tcp://", re.IGNORECASE),
    re.compile(r"stratum\+ssl://", re.IGNORECASE),
    re.compile(r"pool\.[a-z]+\.", re.IGNORECASE),
    re.compile(r"xmr\.", re.IGNORECASE),
    re.compile(r"monero", re.IGNORECASE),
    re.compile(r"coinhive", re.IGNORECASE),
    re.compile(r"coin-hive", re.IGNORECASE),
    re.compile(r"authedmine", re.IGNORECASE),
    re.compile(r"crypto-loot", re.IGNORECASE),
    re.compile(r"webminepool", re.IGNORECASE),
    re.compile(r"ppoi\.org", re.IGNORECASE),
    re.compile(r"minero\.cc", re.IGNORECASE),
    re.compile(r"jsecoin", re.IGNORECASE),
    re.compile(r"webmine\.cz", re.IGNORECASE),
]

# Embedded JS/HTML patterns
EMBEDDED_CODE_PATTERNS = [
    re.compile(r"<script[\s>]", re.IGNORECASE),
    re.compile(r"document\.(write|getElementById|querySelector|cookie)", re.IGNORECASE),
    re.compile(r"\beval\s*\("),
    re.compile(r"\bFunction\s*\("),
    re.compile(r"window\.(location|open|navigator)", re.IGNORECASE),
    re.compile(r"<iframe[\s>]", re.IGNORECASE),
    re.compile(r"<form[\s>]", re.IGNORECASE),
    re.compile(r"\.innerHTML\s*="),
]

# HTML smuggling patterns
SMUGGLING_PATTERNS = [
    re.compile(r"URL\.createObjectURL", re.IGNORECASE),
    re.compile(r"new\s+Blob\s*\(", re.IGNORECASE),
    re.compile(r"\.download\s*="),
    re.compile(r"atob\s*\("),
    re.compile(r"btoa\s*\("),
    re.compile(r"msSaveOrOpenBlob", re.IGNORECASE),
]

# Suspicious import names
SUSPICIOUS_IMPORTS = [
    "performance.now", "Date.now", "WebSocket", "Worker",
    "SharedArrayBuffer", "Atomics", "postMessage",
    "XMLHttpRequest", "fetch", "sendBeacon",
    "crypto.getRandomValues", "crypto.subtle",
]

# URL pattern for IOC extraction
URL_RE = re.compile(r"(?:https?://|//)[^\x00-\x1f\s\"'<>{}\[\]|\\^`]{4,500}", re.IGNORECASE)
IP_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")


def extract_strings(data: bytes, min_length: int = 6) -> List[str]:
    """Extract printable ASCII strings from binary data."""
    strings = []
    current = []
    for byte in data:
        if 0x20 <= byte < 0x7f:
            current.append(chr(byte))
        else:
            if len(current) >= min_length:
                strings.append("".join(current))
            current = []
    if len(current) >= min_length:
        strings.append("".join(current))
    return strings


def parse_wasm(data: bytes) -> Dict[str, Any]:
    """Parse a WASM binary and extract analysis-relevant information."""
    result = {
        "valid": False,
        "version": 0,
        "sections": [],
        "imports": [],
        "exports": [],
        "memory": [],
        "data_strings": [],
        "custom_sections": [],
        "code_stats": {
            "total_ops": 0,
            "crypto_ops": 0,
            "function_count": 0,
        },
    }

    # Check magic and version
    if len(data) < 8 or data[:4] != b"\x00asm":
        return result

    result["version"] = struct.unpack("<I", data[4:8])[0]
    result["valid"] = True

    try:
        from wasm_tob import decode_module
        for section_header, section_data in decode_module(data):
            sec_id = section_header.id
            result["sections"].append({
                "id": sec_id,
                "size": section_header.payload_len,
            })

            if sec_id == SEC_IMPORT:
                _parse_imports(section_data, result)
            elif sec_id == SEC_EXPORT:
                _parse_exports(section_data, result)
            elif sec_id == SEC_MEMORY:
                _parse_memory(section_data, result)
            elif sec_id == SEC_DATA:
                _parse_data(section_data, result)
            elif sec_id == SEC_CODE:
                _parse_code(section_data, result)
            elif sec_id == SEC_CUSTOM:
                _parse_custom(section_data, result)
    except Exception:
        # Fall back to raw string extraction if wasm-tob fails
        result["data_strings"] = extract_strings(data)

    return result


def _parse_imports(section_data, result):
    try:
        for entry in section_data.payload.entries:
            imp = {
                "module": entry.module_str,
                "field": entry.field_str,
                "kind": entry.kind,
            }
            result["imports"].append(imp)
    except Exception:
        pass


def _parse_exports(section_data, result):
    try:
        for entry in section_data.payload.entries:
            exp = {
                "name": entry.field_str,
                "kind": entry.kind,
                "index": entry.index,
            }
            result["exports"].append(exp)
    except Exception:
        pass


def _parse_memory(section_data, result):
    try:
        for entry in section_data.payload.entries:
            mem = {
                "initial_pages": entry.limits.initial,
                "max_pages": getattr(entry.limits, "maximum", None),
            }
            result["memory"].append(mem)
    except Exception:
        pass


def _parse_data(section_data, result):
    try:
        for entry in section_data.payload.entries:
            raw = entry.data.tobytes() if hasattr(entry.data, "tobytes") else bytes(entry.data)
            strings = extract_strings(raw, min_length=4)
            result["data_strings"].extend(strings)
    except Exception:
        pass


def _parse_code(section_data, result):
    try:
        from wasm_tob import decode_bytecode
        bodies = section_data.payload.bodies
        result["code_stats"]["function_count"] = len(bodies)
        total_ops = 0
        crypto_ops = 0
        for body in bodies:
            for op in decode_bytecode(body.code):
                total_ops += 1
                if op.op.id in CRYPTO_OPS:
                    crypto_ops += 1
        result["code_stats"]["total_ops"] = total_ops
        result["code_stats"]["crypto_ops"] = crypto_ops
    except Exception:
        pass


def _parse_custom(section_data, result):
    try:
        name = section_data.payload.name
        raw = bytes(section_data.payload.data) if hasattr(section_data.payload, "data") else b""
        strings = extract_strings(raw, min_length=4)
        result["custom_sections"].append({
            "name": name,
            "size": len(raw),
            "strings": strings[:50],
        })
    except Exception:
        pass
