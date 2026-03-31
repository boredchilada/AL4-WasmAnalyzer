import os
import subprocess
from typing import Dict, Any, Optional

from assemblyline_v4_service.common.base import ServiceBase
from assemblyline_v4_service.common.request import ServiceRequest
from assemblyline_v4_service.common.result import Result, ResultSection, BODY_FORMAT

from models.wasm_parser import parse_wasm
from models.result_processor import ResultProcessor


class WasmAnalyzer(ServiceBase):
    def __init__(self, config: Optional[Dict[str, Any]] = None):
        super().__init__(config)

    def start(self):
        self.log.info("WasmAnalyzer starting")
        # Verify wabt tools are available
        try:
            version = subprocess.check_output(["wasm-objdump", "--version"],
                                              stderr=subprocess.STDOUT).decode().strip()
            self.log.info(f"wabt version: {version}")
        except Exception as e:
            self.log.warning(f"wabt tools not available: {e}")

    def get_tool_version(self):
        try:
            import wasm_tob
            return getattr(wasm_tob, "__version__", "unknown")
        except Exception:
            return "unknown"

    def execute(self, request: ServiceRequest) -> None:
        result = Result()
        request.result = result

        file_path = request.file_path

        # Read and validate
        with open(file_path, "rb") as f:
            data = f.read()

        if len(data) < 8 or data[:4] != b"\x00asm":
            self.log.warning("File does not appear to be a valid WASM module")
            return

        # Parse WASM
        parsed = parse_wasm(data)

        if not parsed["valid"]:
            section = ResultSection("Invalid WASM Module", body_format=BODY_FORMAT.TEXT)
            section.add_line("File has WASM magic bytes but could not be parsed")
            result.add_section(section)
            return

        # Process results
        processor = ResultProcessor(result, request, self.log)
        processor.process(parsed)

        # Generate decompiled output as supplementary
        extract_decompiled = self.config.get("extract_decompiled", True)
        max_size = self.config.get("max_decompile_size", 10 * 1024 * 1024)

        if extract_decompiled and os.path.getsize(file_path) < max_size:
            self._generate_decompiled(file_path, request)
            self._generate_objdump(file_path, request)

    def _generate_decompiled(self, file_path: str, request: ServiceRequest) -> None:
        """Run wasm-decompile and add output as supplementary file."""
        out_path = os.path.join(self.working_directory, "decompiled.dcmp")
        try:
            proc = subprocess.run(
                ["wasm-decompile", file_path, "-o", out_path],
                capture_output=True, text=True, timeout=60,
            )
            if proc.returncode == 0 and os.path.exists(out_path):
                size = os.path.getsize(out_path)
                if size > 0:
                    request.add_supplementary(
                        out_path, "decompiled.dcmp",
                        "Decompiled WASM output from wasm-decompile",
                    )
        except Exception as e:
            self.log.warning(f"wasm-decompile failed: {e}")

    def _generate_objdump(self, file_path: str, request: ServiceRequest) -> None:
        """Run wasm-objdump and add output as supplementary file."""
        out_path = os.path.join(self.working_directory, "objdump.txt")
        try:
            proc = subprocess.run(
                ["wasm-objdump", "-x", file_path],
                capture_output=True, text=True, timeout=60,
            )
            if proc.returncode == 0 and proc.stdout:
                with open(out_path, "w") as f:
                    f.write(proc.stdout)
                request.add_supplementary(
                    out_path, "objdump.txt",
                    "WASM module structure from wasm-objdump -x",
                )
        except Exception as e:
            self.log.warning(f"wasm-objdump failed: {e}")
