# Volatility 3 plugin: Linux SGX/SMI forensic degradation triage
#
# Purpose
# -------
# This plugin is a defensive triage plugin for SGX-aware memory investigations
# where the hypothesis is not "read the enclave", but "determine whether the
# enclave was degraded from outside, for example through SMM/SMI manipulation".
#
# It does NOT read EPC contents in release mode and it does NOT prove SMM
# compromise by itself. It correlates process-level SGX artifacts in a memory
# image with optional auxiliary evidence produced during acquisition, such as
# CHIPSEC JSON/text output and an SMI counter timeline.
#
# Install
# -------
# Copy this file into volatility3/volatility3/plugins/linux/ and run, for example:
#
#   python3 vol.py -f mem.raw linux.sgx_smi_degradation.SgxSmiDegradation \
#       --max-vma-read 1048576 \
#       --scan-memory \
#       --chipsec-report file:///jaberme/host01/chipsec_report.json \
#       --smi-timeline file:///jaberme/host01/smi_timeline.csv
#
# Auxiliary file formats
# ----------------------
# chipsec_report may be CHIPSEC JSON, text, or a collected console log. The plugin
# searches for lock/protection failure patterns in relevant modules.
# smi_timeline may be a simple CSV or text file containing timestamps and numeric
# SMI counter values. The plugin estimates bursts from counter deltas.

from __future__ import annotations

import csv
import io
import json
import re
from typing import Dict, Iterable, Iterator, List, Optional, Sequence, Tuple
from urllib.parse import unquote, urlparse

from volatility3.framework import exceptions, interfaces, renderers
from volatility3.framework.configuration import requirements
from volatility3.plugins.linux import pslist


class SgxSmiDegradation(interfaces.plugins.PluginInterface):
    """Triages SGX artifacts and SMI-degradation indicators in Linux memory images."""

    _required_framework_version = (2, 0, 0)
    _version = (1, 0, 0)

    ENCLU = b"\x0f\x01\xd7"
    ENCLS = b"\x0f\x01\xcf"

    SGX_TEXT_PATTERNS = (
        b"/dev/sgx",
        b"/dev/isgx",
        b"sgx_enclave",
        b"sgx_provision",
        b"libsgx_urts",
        b"libsgx_enclave_common",
        b"libsgx_dcap",
        b"sgx_ecall",
        b"sgx_ocall",
        b"ocall_table",
        b"ecall_table",
        b"oe_enclave",
        b"openenclave",
        b"graphene-sgx",
        b"sgx-lkl",
        b"EDBGRD",
        b"EDBGWR",
    )

    SGX_NAME_PATTERNS = (
        "sgx",
        "isgx",
        "aesm",
        "enclave",
        "libsgx",
        "urts",
        "openenclave",
        "graphene",
        "ocall",
        "ecall",
    )

    CHIPSEC_INTERESTING_MODULES = (
        "common.smm",
        "common.smrr",
        "common.smm_dma",
        "common.bios_smi",
        "common.smm_code_chk",
        "common.smm_code_chk_en",
        "common.bios_wp",
        "common.spi_lock",
        "tools.smm.smm_ptr",
        "tools.uefi.scan_image",
        "tools.uefi.whitelist",
    )

    CHIPSEC_BAD_WORDS = (
        "fail",
        "failed",
        "warning",
        "warn",
        "vulnerable",
        "unlocked",
        "not locked",
        "not set",
        "disabled",
        "misconfigured",
        "bad",
        "insecure",
        "not protected",
    )

    @classmethod
    def get_requirements(cls) -> List[interfaces.configuration.RequirementInterface]:
        return [
            requirements.ModuleRequirement(
                name="kernel",
                description="Linux kernel module",
                architectures=["Intel32", "Intel64"],
            ),
            requirements.BooleanRequirement(
                name="scan-memory",
                description="Scan readable process VMAs for ENCLU/ENCLS and SGX/OCALL strings",
                default=True,
                optional=True,
            ),
            requirements.IntRequirement(
                name="max-vma-read",
                description="Maximum bytes to read from each VMA during heuristic scanning",
                default=1048576,
                optional=True,
            ),
            requirements.IntRequirement(
                name="min-ff-pages",
                description="Minimum all-0xFF 4 KiB pages in a sampled VMA to report an EPC-like blind spot",
                default=2,
                optional=True,
            ),
            requirements.URIRequirement(
                name="chipsec-report",
                description="Optional CHIPSEC JSON/text report collected during acquisition",
                optional=True,
            ),
            requirements.URIRequirement(
                name="smi-timeline",
                description="Optional SMI counter/timeline file, CSV or text",
                optional=True,
            ),
            requirements.IntRequirement(
                name="smi-burst-threshold",
                description="Delta threshold used to flag SMI bursts in auxiliary timeline",
                default=100,
                optional=True,
            ),
        ]

    @staticmethod
    def _safe_int(value, default: int = 0) -> int:
        try:
            return int(value)
        except Exception:
            return default

    @staticmethod
    def _uri_to_path(uri: Optional[str]) -> Optional[str]:
        if not uri:
            return None
        parsed = urlparse(uri)
        if parsed.scheme in ("", "file"):
            return unquote(parsed.path if parsed.scheme == "file" else uri)
        return None

    @classmethod
    def _read_aux_text(cls, uri: Optional[str]) -> str:
        path = cls._uri_to_path(uri)
        if not path:
            return ""
        try:
            with open(path, "rb") as f:
                raw = f.read(16 * 1024 * 1024)
            return raw.decode("utf-8", errors="replace")
        except Exception:
            return ""

    @classmethod
    def _extract_chipsec_findings(cls, text: str) -> List[Tuple[str, str, str]]:
        """Return [(module, severity, evidence), ...] from CHIPSEC output.

        The parser intentionally accepts loose JSON and text because CHIPSEC
        reports differ depending on version and runner wrapper.
        """
        findings: List[Tuple[str, str, str]] = []
        if not text.strip():
            return findings

        lowered = text.lower()

        # JSON first: recurse through dicts and lists and keep suspicious leaves.
        try:
            data = json.loads(text)

            def walk(obj, path=""):
                if isinstance(obj, dict):
                    name = str(obj.get("module", obj.get("name", path)))
                    status = " ".join(str(obj.get(k, "")) for k in ("result", "status", "severity", "message"))
                    blob = json.dumps(obj, ensure_ascii=False)[:500]
                    hay = (name + " " + status + " " + blob).lower()
                    if any(m in hay for m in cls.CHIPSEC_INTERESTING_MODULES) and any(b in hay for b in cls.CHIPSEC_BAD_WORDS):
                        severity = "HIGH" if any(x in hay for x in ("fail", "vulnerable", "unlocked", "not locked")) else "MEDIUM"
                        findings.append((name, severity, blob))
                    for k, v in obj.items():
                        walk(v, f"{path}.{k}" if path else str(k))
                elif isinstance(obj, list):
                    for i, v in enumerate(obj):
                        walk(v, f"{path}[{i}]")

            walk(data)
            if findings:
                return findings[:50]
        except Exception:
            pass

        # Text fallback: line-oriented scan.
        for line in text.splitlines():
            line_l = line.lower()
            if not any(m in line_l for m in cls.CHIPSEC_INTERESTING_MODULES):
                continue
            if not any(b in line_l for b in cls.CHIPSEC_BAD_WORDS):
                continue
            module = next((m for m in cls.CHIPSEC_INTERESTING_MODULES if m in line_l), "chipsec")
            severity = "HIGH" if any(x in line_l for x in ("fail", "failed", "vulnerable", "unlocked", "not locked")) else "MEDIUM"
            findings.append((module, severity, line.strip()[:500]))
        return findings[:50]

    @classmethod
    def _extract_smi_findings(cls, text: str, threshold: int) -> List[Tuple[str, str, str]]:
        """Parse SMI timeline/counter samples and flag bursts.

        Expected examples:
            timestamp,cpu,total_smi
            2026-05-15T12:00:00,0,12033
            2026-05-15T12:00:01,0,12390

        or loose text containing increasing counter values. This is deliberately
        conservative: it only raises an indicator when a numeric delta exceeds
        the configured threshold.
        """
        if not text.strip():
            return []

        numbers: List[int] = []
        # Try CSV with an obvious SMI/counter column.
        try:
            sniffer = csv.Sniffer()
            sample = text[:4096]
            dialect = sniffer.sniff(sample)
            reader = csv.DictReader(io.StringIO(text), dialect=dialect)
            fields = [f or "" for f in (reader.fieldnames or [])]
            candidates = [f for f in fields if re.search(r"smi|count|counter|total", f, re.I)]
            for row in reader:
                for c in candidates:
                    value = row.get(c)
                    if value is not None and re.match(r"^\s*\d+\s*$", value):
                        numbers.append(int(value))
                        break
        except Exception:
            pass

        # Fallback: collect integers from lines mentioning SMI.
        if not numbers:
            for line in text.splitlines():
                if "smi" not in line.lower():
                    continue
                for n in re.findall(r"\b\d+\b", line):
                    numbers.append(int(n))

        findings: List[Tuple[str, str, str]] = []
        if len(numbers) < 2:
            return findings
        deltas = [b - a for a, b in zip(numbers, numbers[1:]) if b >= a]
        if not deltas:
            return findings
        max_delta = max(deltas)
        avg_delta = sum(deltas) / len(deltas)
        if max_delta >= threshold:
            findings.append((
                "SMI_TIMELINE",
                "MEDIUM" if max_delta < threshold * 5 else "HIGH",
                f"SMI counter burst detected: max_delta={max_delta}, avg_delta={avg_delta:.2f}, samples={len(numbers)}",
            ))
        return findings

    @staticmethod
    def _vma_name(vma, task) -> str:
        for attr in ("get_name", "get_file_name"):
            try:
                fn = getattr(vma, attr)
                value = fn(task) if attr == "get_file_name" else fn(task)
                if value:
                    return str(value)
            except Exception:
                pass
        try:
            vm_file = vma.vm_file
            if vm_file:
                return str(vm_file.get_full_path())
        except Exception:
            pass
        return ""

    @classmethod
    def _name_indicators(cls, name: str) -> List[str]:
        n = name.lower()
        return [f"name:{p}" for p in cls.SGX_NAME_PATTERNS if p in n]

    @classmethod
    def _scan_buffer(cls, data: bytes, min_ff_pages: int) -> Tuple[List[str], int]:
        indicators: List[str] = []
        score = 0

        enclu_count = data.count(cls.ENCLU)
        encls_count = data.count(cls.ENCLS)
        if enclu_count:
            indicators.append(f"ENCLU={enclu_count}")
            score += min(4, 1 + enclu_count)
        if encls_count:
            indicators.append(f"ENCLS={encls_count}")
            score += min(3, encls_count)

        for pat in cls.SGX_TEXT_PATTERNS:
            if pat in data:
                try:
                    label = pat.decode("ascii", errors="ignore")
                except Exception:
                    label = repr(pat)
                indicators.append(f"string:{label}")
                score += 1

        # EPC/PRM pages normally cannot be read in clear. Some SGX-aware dumps
        # preserve the blind spot as 0xFF pages. This is not proof of SGX by
        # itself, but it is useful when correlated with ENCLU/OCALL artifacts.
        page_size = 4096
        pages = len(data) // page_size
        ff_pages = 0
        if pages:
            ff_page = b"\xff" * page_size
            for i in range(pages):
                if data[i * page_size:(i + 1) * page_size] == ff_page:
                    ff_pages += 1
        if ff_pages >= min_ff_pages:
            indicators.append(f"all_0xff_pages={ff_pages}/{pages}")
            score += 3

        return indicators, score

    @staticmethod
    def _task_comm(task) -> str:
        try:
            return task.comm.cast("string", max_length=64, errors="replace")
        except Exception:
            try:
                return str(task.comm)
            except Exception:
                return ""

    def _iter_vmas(self, task) -> Iterable[Tuple[int, int, str, object]]:
        try:
            mm = task.mm
            if not mm:
                return []
        except Exception:
            return []

        try:
            return [(int(vma.vm_start), int(vma.vm_end), self._vma_name(vma, task), vma) for vma in mm.get_mmap_iter()]
        except Exception:
            return []

    def _generator(self) -> Iterator[Tuple[int, Tuple[str, int, str, str, str, int, str, str]]]:
        kernel = self.context.modules[self.config["kernel"]]
        scan_memory = bool(self.config.get("scan-memory", True))
        max_vma_read = max(4096, self._safe_int(self.config.get("max-vma-read", 1048576), 1048576))
        min_ff_pages = max(1, self._safe_int(self.config.get("min-ff-pages", 2), 2))
        smi_threshold = max(1, self._safe_int(self.config.get("smi-burst-threshold", 100), 100))

        chipsec_text = self._read_aux_text(self.config.get("chipsec-report"))
        smi_text = self._read_aux_text(self.config.get("smi-timeline"))

        for module, severity, evidence in self._extract_chipsec_findings(chipsec_text):
            interpretation = (
                "Plataforma o SMM no plenamente confiable. Correlacionar con SPI, PCR0/PCRs, "
                "SMRAM y cadena de adquisición antes de interpretar el dump SGX."
            )
            score = 8 if severity == "HIGH" else 5
            yield (0, ("CHIPSEC", 0, "platform", module, evidence, score, severity, interpretation))

        for module, severity, evidence in self._extract_smi_findings(smi_text, smi_threshold):
            interpretation = (
                "Ráfaga de SMI compatible con degradación por AEX repetidos o instrumentación SMM. "
                "No demuestra intrusión; exige correlación temporal con actividad del enclave."
            )
            score = 7 if severity == "HIGH" else 4
            yield (0, ("SMI", 0, "platform", module, evidence, score, severity, interpretation))

        try:
            tasks = pslist.PsList.list_tasks(self.context, kernel.name)
        except exceptions.SymbolError:
            return

        for task in tasks:
            pid = self._safe_int(getattr(task, "pid", 0), 0)
            comm = self._task_comm(task)
            try:
                proc_layer_name = task.add_process_layer()
            except Exception:
                proc_layer_name = None

            for start, end, name, _vma in self._iter_vmas(task):
                if end <= start:
                    continue
                indicators = self._name_indicators(name)
                score = len(indicators)
                sample_note = "metadata-only"

                if scan_memory and proc_layer_name:
                    try:
                        layer = self.context.layers[proc_layer_name]
                        to_read = min(max_vma_read, end - start)
                        data = layer.read(start, to_read, pad=True)
                        buf_indicators, buf_score = self._scan_buffer(data, min_ff_pages)
                        indicators.extend(buf_indicators)
                        score += buf_score
                        sample_note = f"sampled={to_read}B"
                    except Exception as exc:
                        sample_note = f"unreadable:{exc.__class__.__name__}"

                if not indicators:
                    continue

                confidence = "LOW"
                if score >= 8:
                    confidence = "HIGH"
                elif score >= 4:
                    confidence = "MEDIUM"

                vma_repr = f"0x{start:x}-0x{end:x} {name}".strip()
                interpretation = self._interpret_process_indicators(indicators, score, sample_note)
                yield (0, ("PROCESS", pid, comm, vma_repr, ", ".join(sorted(set(indicators)))[:800], score, confidence, interpretation))

    @staticmethod
    def _interpret_process_indicators(indicators: Sequence[str], score: int, note: str) -> str:
        text = " ".join(indicators).lower()
        if "enclu" in text and ("ocall" in text or "ecall" in text):
            return (
                f"Proceso anfitrión SGX con transición ENCLU e interfaz ECALL/OCALL visible ({note}). "
                "Examinar memoria no confiable, tablas OCALL, GOT/PLT y cronología SMI."
            )
        if "all_0xff_pages" in text:
            return (
                f"Posible mancha ciega EPC/PRM preservada como 0xFF en el volcado ({note}). "
                "Tratar como ausencia trazable de evidencia, no como contenido benigno."
            )
        if "libsgx" in text or "/dev/sgx" in text or "isgx" in text:
            return (
                f"Artefactos de runtime o driver SGX en el proceso ({note}). "
                "Correlacionar con enclaves cargados, DCAP/isgx, microcódigo y firmware."
            )
        if score >= 4:
            return f"Conjunto de indicadores SGX no concluyente pero relevante para triage ({note})."
        return f"Indicador débil; conservar para correlación posterior ({note})."

    def run(self) -> renderers.TreeGrid:
        return renderers.TreeGrid(
            [
                ("Scope", str),
                ("PID", int),
                ("Process", str),
                ("Object", str),
                ("Evidence", str),
                ("Score", int),
                ("Confidence", str),
                ("Interpretation", str),
            ],
            self._generator(),
        )
