"""Static file and attachment analyzer.

Nothing is executed, extracted to disk, or uploaded. The analyzer inspects
magic bytes, archive metadata, macro storage, PDF actions, and script
patterns, then optionally looks up the SHA-256 hash with VirusTotal.
"""

from __future__ import annotations

import io
import math
import zipfile
from collections import Counter

from ..intel import IntelClient
from ..models import AnalysisResult, Severity, Signal
from ..scoring import finalize
from ..utils import (
    DANGEROUS_EXTENSIONS,
    MIME_BY_EXTENSION,
    detect_mime,
    double_extension,
    file_extension,
    format_bytes,
    hash_bytes,
)

_OOXML_EXTS = {"docx", "xlsx", "pptx", "docm", "xlsm", "pptm", "dotm", "xltm", "potm"}
_OLE_EXTS = {"doc", "xls", "ppt", "msg", "msi"}
_ARCHIVE_EXTS = {"zip", "jar", "apk", "docx", "xlsx", "pptx", "docm", "xlsm", "pptm", "7z", "rar", "tar", "gz"}


def analyze_file_bytes(
    data: bytes,
    filename: str = "upload.bin",
    *,
    use_intel: bool = False,
    online: bool = True,
    intel: IntelClient | None = None,
) -> AnalysisResult:
    result = AnalysisResult(analyzer="File", target=filename or "upload.bin")
    if not data:
        result.error = "Empty file"
        return finalize(result)
    if len(data) > 25 * 1024 * 1024:
        result.error = "File is larger than the 25 MB analysis limit"
        return finalize(result)

    ext = file_extension(filename)
    mime = detect_mime(data, filename)
    hashes = hash_bytes(data)
    result.metadata.update(
        {
            "filename": filename,
            "size": format_bytes(len(data)),
            "size_bytes": len(data),
            "extension": ext or "(none)",
            "mime": mime,
            "hashes": hashes,
            "entropy": round(_byte_entropy(data), 2),
        }
    )

    result.add(
        Signal(
            id="file.hashed",
            title="File fingerprinted",
            severity=Severity.INFO,
            category="file",
            description="A SHA-256 hash was calculated locally; the file itself was not uploaded.",
            evidence=hashes["sha256"],
            weight=0,
        )
    )

    _extension_signals(result, filename, ext, mime)
    _signature_signals(result, data, ext, mime)
    _ole_signals(result, data, ext)
    _ooxml_signals(result, data, ext)
    _pdf_signals(result, data, ext)
    _archive_signals(result, data, ext)
    _script_signals(result, data, ext, mime)

    if use_intel and intel:
        vt = intel.virustotal_file(hashes["sha256"])
        result.metadata["virustotal"] = vt.to_dict()
        if vt.error:
            result.metadata.setdefault("intel_errors", []).append(f"VirusTotal: {vt.error}")
        elif vt.found:
            if vt.malicious >= 3:
                weight, severity, title = 90, Severity.CRITICAL, "VirusTotal: multiple engines flag this file"
            elif vt.malicious >= 1:
                weight, severity, title = 70, Severity.HIGH, "VirusTotal: an engine flags this file"
            elif vt.suspicious >= 2:
                weight, severity, title = 45, Severity.MEDIUM, "VirusTotal: suspicious file reputation"
            else:
                weight, severity, title = 0, Severity.INFO, "VirusTotal: no detections for this hash"
            result.add(
                Signal(
                    id="intel.virustotal_file",
                    title=title,
                    severity=severity,
                    category="intel",
                    description="Crowdsourced multi-engine reputation result for the SHA-256 hash.",
                    evidence=f"malicious={vt.malicious}, suspicious={vt.suspicious}, harmless={vt.harmless}",
                    weight=weight,
                    source="VirusTotal",
                )
            )
        else:
            result.add(
                Signal(
                    id="intel.virustotal_unknown",
                    title="Hash not previously seen by VirusTotal",
                    severity=Severity.INFO,
                    category="intel",
                    description="An unknown hash is not proof of safety; new malware is often unseen.",
                    evidence=hashes["sha256"][:16] + "…",
                    weight=0,
                    source="VirusTotal",
                )
            )

    result.recommendations = [
        "Do not open the file unless you independently trust the sender and expected it.",
        "Never enable macros or click through security warnings in an unexpected document.",
        "If the file is suspicious, quarantine it and report it to your security team.",
        "When in doubt, verify with the sender through a different channel.",
    ]
    return finalize(result)


def _extension_signals(result: AnalysisResult, filename: str, ext: str, mime: str) -> None:
    if ext in DANGEROUS_EXTENSIONS:
        result.add(
            Signal(
                id="file.dangerous_extension",
                title="Executable or script extension",
                severity=Severity.HIGH,
                category="file",
                description="This file type can run code or install software.",
                evidence=f".{ext}",
                weight=30,
            )
        )

    double = double_extension(filename)
    if double:
        result.add(
            Signal(
                id="file.double_extension",
                title="Double extension disguises the real file type",
                severity=Severity.HIGH,
                category="file",
                description="The name looks like a document but the final extension is executable.",
                evidence=double,
                weight=35,
            )
        )

    expected = MIME_BY_EXTENSION.get(ext)
    if expected and mime and mime != "application/octet-stream":
        compatible = (
            (ext in _OOXML_EXTS and mime == "application/zip")
            or (ext in _OLE_EXTS and mime == "application/x-ole-storage")
            or (ext in {"jpg", "jpeg"} and mime == "image/jpeg")
        )
        if not compatible and expected != mime:
            result.add(
                Signal(
                    id="file.mime_mismatch",
                    title="File content does not match its extension",
                    severity=Severity.MEDIUM,
                    category="file",
                    description="Attackers often rename executables or archives to look harmless.",
                    evidence=f".{ext} claims {expected}; content looks like {mime}",
                    weight=25,
                )
            )


def _signature_signals(result: AnalysisResult, data: bytes, ext: str, mime: str) -> None:
    if mime in {"application/x-dosexec", "application/x-elf"}:
        result.add(
            Signal(
                id="file.executable",
                title="File contains executable code",
                severity=Severity.CRITICAL,
                category="file",
                description="The file has an executable binary signature.",
                evidence=mime,
                weight=65,
            )
        )
    if data.startswith(b"L\x00\x00\x00\x01\x14\x02\x00"):
        result.add(
            Signal(
                id="file.lnk",
                title="Windows shortcut (.lnk) file",
                severity=Severity.HIGH,
                category="file",
                description="Shortcut files can launch scripts or remote payloads.",
                evidence="LNK signature",
                weight=50,
            )
        )
    if len(data) > 32774 and data[32769:32774] == b"CD001":
        result.add(
            Signal(
                id="file.iso",
                title="Disk image (ISO) file",
                severity=Severity.HIGH,
                category="file",
                description="ISO images can carry executables past some email filters.",
                evidence="ISO9660 signature",
                weight=45,
            )
        )
    if data.startswith(b"\xe4\x52\x5c\x7b"):
        result.add(
            Signal(
                id="file.onenote",
                title="OneNote document",
                severity=Severity.MEDIUM,
                category="file",
                description="OneNote files have been used to deliver embedded scripts.",
                evidence="OneNote signature",
                weight=35,
            )
        )
    if data.lstrip().lower().startswith(b"{\\rtf") and (
        b"\\objupdate" in data.lower() or b"\\objdata" in data.lower()
    ):
        result.add(
            Signal(
                id="file.rtf_object",
                title="RTF document contains an embedded object",
                severity=Severity.HIGH,
                category="file",
                description="Embedded RTF objects have been used in exploit chains.",
                evidence="\\objupdate / \\objdata",
                weight=40,
            )
        )
    if ext == "url":
        result.add(
            Signal(
                id="file.url_shortcut",
                title="Internet shortcut file",
                severity=Severity.MEDIUM,
                category="file",
                description="A .url file opens a website and can hide the destination.",
                evidence=result.target,
                weight=25,
            )
        )


def _ole_signals(result: AnalysisResult, data: bytes, ext: str) -> None:
    if not data.startswith(b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1"):
        return
    try:
        import olefile

        with olefile.OleFileIO(io.BytesIO(data)) as ole:
            streams = ["/".join(entry) for entry in ole.listdir()]
            lowered = [stream.lower() for stream in streams]
            if any("vba" in stream or "macros" in stream for stream in lowered):
                result.add(
                    Signal(
                        id="file.ole_macro",
                        title="Office document contains VBA macros",
                        severity=Severity.CRITICAL,
                        category="file",
                        description="Macros can download or run code when enabled.",
                        evidence=", ".join(streams[:8]),
                        weight=55,
                    )
                )
            if ole.exists("EncryptionInfo"):
                result.add(
                    Signal(
                        id="file.ole_encrypted",
                        title="Office document is encrypted or password-protected",
                        severity=Severity.MEDIUM,
                        category="file",
                        description="Encryption can hide malicious content from scanners.",
                        evidence="EncryptionInfo stream",
                        weight=20,
                    )
                )
    except Exception:
        return


def _ooxml_signals(result: AnalysisResult, data: bytes, ext: str) -> None:
    if not zipfile.is_zipfile(io.BytesIO(data)):
        return
    try:
        with zipfile.ZipFile(io.BytesIO(data)) as archive:
            names = archive.namelist()[:2000]
    except Exception:
        return

    lowered = [name.lower() for name in names]
    if any(name.endswith("vbaproject.bin") for name in lowered):
        result.add(
            Signal(
                id="file.ooxml_macro",
                title="OOXML document contains VBA macros",
                severity=Severity.CRITICAL,
                category="file",
                description="Macro-enabled Office files are a common malware delivery method.",
                evidence="vbaProject.bin",
                weight=55,
            )
        )
    if any("/embeddings/" in name or name.startswith("embeddings/") for name in lowered):
        result.add(
            Signal(
                id="file.ooxml_embedded",
                title="Office document contains embedded objects",
                severity=Severity.HIGH,
                category="file",
                description="Embedded files can hide executables or additional payloads.",
                evidence="embeddings/",
                weight=35,
            )
        )
    if any("externallinks" in name for name in lowered):
        result.add(
            Signal(
                id="file.ooxml_external_links",
                title="Office document contains external links",
                severity=Severity.MEDIUM,
                category="file",
                description="External links can fetch content or leak information.",
                evidence="externalLinks",
                weight=20,
            )
        )
    if any("activex" in name for name in lowered):
        result.add(
            Signal(
                id="file.ooxml_activex",
                title="Office document contains ActiveX content",
                severity=Severity.HIGH,
                category="file",
                description="ActiveX controls can execute code.",
                evidence="activeX",
                weight=35,
            )
        )


def _pdf_signals(result: AnalysisResult, data: bytes, ext: str) -> None:
    if not data.startswith(b"%PDF"):
        return
    lowered = data.lower()
    checks = [
        (b"/javascript", "PDF contains JavaScript", 40, Severity.HIGH),
        (b"/launch", "PDF contains a launch action", 45, Severity.HIGH),
        (b"/embeddedfile", "PDF contains an embedded file", 30, Severity.MEDIUM),
        (b"/openaction", "PDF runs an action on open", 20, Severity.MEDIUM),
        (b"/aa", "PDF contains an automatic action", 20, Severity.MEDIUM),
        (b"/richmedia", "PDF contains rich media", 25, Severity.MEDIUM),
    ]
    for needle, title, weight, severity in checks:
        if needle in lowered:
            result.add(
                Signal(
                    id=f"file.pdf_{needle.decode('latin-1').strip('/')}",
                    title=title,
                    severity=severity,
                    category="file",
                    description="Active PDF content can execute code or fetch remote resources.",
                    evidence=needle.decode("latin-1"),
                    weight=weight,
                )
            )


def _archive_signals(result: AnalysisResult, data: bytes, ext: str) -> None:
    if not zipfile.is_zipfile(io.BytesIO(data)):
        return
    try:
        with zipfile.ZipFile(io.BytesIO(data)) as archive:
            infos = archive.infolist()[:2000]
    except Exception:
        return

    total_uncompressed = sum(info.file_size for info in infos)
    total_compressed = max(1, sum(info.compress_size for info in infos))
    result.metadata["archive_entries"] = len(infos)
    result.metadata["archive_uncompressed"] = format_bytes(total_uncompressed)

    if len(infos) > 1000 or total_uncompressed > 200 * 1024 * 1024 or (
        total_uncompressed > 20 * 1024 * 1024 and total_uncompressed / total_compressed > 100
    ):
        result.add(
            Signal(
                id="file.archive_bomb",
                title="Archive may be a decompression bomb",
                severity=Severity.HIGH,
                category="file",
                description="The archive expands to an unusually large size or contains too many entries.",
                evidence=f"{len(infos)} entries, {format_bytes(total_uncompressed)} uncompressed",
                weight=50,
            )
        )

    dangerous_entries = [
        info.filename
        for info in infos
        if file_extension(info.filename) in DANGEROUS_EXTENSIONS
        and not (ext in _OOXML_EXTS and info.filename.lower().endswith("vbaproject.bin"))
    ]
    if dangerous_entries:
        result.add(
            Signal(
                id="file.archive_executable",
                title="Archive contains executable or script files",
                severity=Severity.HIGH,
                category="file",
                description="Archives are often used to bypass email attachment filters.",
                evidence=", ".join(dangerous_entries[:6]),
                weight=40,
            )
        )

    traversal = [info.filename for info in infos if "../" in info.filename or info.filename.startswith("/")]
    if traversal:
        result.add(
            Signal(
                id="file.archive_traversal",
                title="Archive contains path traversal entries",
                severity=Severity.HIGH,
                category="file",
                description="The archive may try to write files outside the extraction directory.",
                evidence=", ".join(traversal[:5]),
                weight=35,
            )
        )

    if any(info.flag_bits & 0x1 for info in infos):
        result.add(
            Signal(
                id="file.archive_encrypted",
                title="Archive is password-protected",
                severity=Severity.MEDIUM,
                category="file",
                description="Encrypted archives can hide malware from scanners.",
                evidence="ZIP encryption flag set",
                weight=20,
            )
        )


def _script_signals(result: AnalysisResult, data: bytes, ext: str, mime: str) -> None:
    text = data[:200_000].decode("utf-8", errors="ignore").lower()
    if ext in {"ps1", "vbs", "js", "bat", "cmd", "hta", "wsf", "sh"} or mime in {
        "text/x-script",
        "text/javascript",
    }:
        patterns = [
            ("invoke-expression", "PowerShell Invoke-Expression", 40),
            ("iex(", "PowerShell IEX", 35),
            ("frombase64string", "Base64-decoded payload", 35),
            ("downloadstring", "Remote script download", 35),
            ("powershell -enc", "Encoded PowerShell command", 40),
            ("curl ", "Network download command", 20),
            ("wget ", "Network download command", 20),
            ("eval(", "Dynamic code evaluation", 25),
            ("exec(", "Dynamic code execution", 25),
        ]
        hits = [(label, weight) for needle, label, weight in patterns if needle in text]
        for label, weight in hits[:4]:
            result.add(
                Signal(
                    id=f"file.script_{label.lower().replace(' ', '_')}",
                    title=f"Script contains {label}",
                    severity=Severity.HIGH,
                    category="file",
                    description="The script uses behaviour commonly seen in malware loaders.",
                    evidence=label,
                    weight=weight,
                )
            )

    if mime == "text/html" or ext in {"html", "htm"}:
        if "<script" in text and ("atob(" in text or "base64" in text):
            result.add(
                Signal(
                    id="file.html_smuggling",
                    title="HTML may contain an encoded payload",
                    severity=Severity.HIGH,
                    category="file",
                    description="HTML smuggling hides payloads inside a web page.",
                    evidence="script + base64/atob",
                    weight=40,
                )
            )
        if "<iframe" in text:
            result.add(
                Signal(
                    id="file.html_iframe",
                    title="HTML contains an iframe",
                    severity=Severity.MEDIUM,
                    category="file",
                    description="Iframes can load untrusted third-party content.",
                    evidence="<iframe>",
                    weight=15,
                )
            )


def _byte_entropy(data: bytes) -> float:
    if not data:
        return 0.0
    counts = Counter(data)
    length = len(data)
    return -sum((count / length) * math.log2(count / length) for count in counts.values())
