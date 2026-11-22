import io
import zipfile

from phishguard.analyzers.file import analyze_file_bytes
from phishguard.models import Verdict


def test_executable_with_double_extension():
    result = analyze_file_bytes(b"MZ" + b"\x00" * 200, "invoice.pdf.exe", online=False)
    ids = {signal.id for signal in result.signals}
    assert "file.executable" in ids
    assert "file.double_extension" in ids
    assert result.verdict is Verdict.MALICIOUS


def test_pdf_javascript():
    result = analyze_file_bytes(b"%PDF-1.7\n/JavaScript /OpenAction\n", "invoice.pdf", online=False)
    assert any(signal.id.startswith("file.pdf_") for signal in result.signals)
    assert result.score >= 35


def test_ooxml_macro():
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w") as archive:
        archive.writestr("word/document.xml", "<xml/>")
        archive.writestr("word/vbaProject.bin", b"fake macro")
    result = analyze_file_bytes(buffer.getvalue(), "invoice.docx", online=False)
    assert any(signal.id == "file.ooxml_macro" for signal in result.signals)


def test_archive_with_executable_and_traversal():
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w") as archive:
        archive.writestr("../../payload.exe", b"MZ" + b"\x00" * 10)
    result = analyze_file_bytes(buffer.getvalue(), "files.zip", online=False)
    ids = {signal.id for signal in result.signals}
    assert "file.archive_executable" in ids
    assert "file.archive_traversal" in ids


def test_plain_text_is_not_malicious():
    result = analyze_file_bytes(b"hello world\n", "notes.txt", online=False)
    assert result.verdict is Verdict.LIKELY_SAFE
    assert result.score < 35
def test_empty_file_returns_error():
    result = analyze_file_bytes(
        b"",
        "empty.txt",
        online=False,
    )

    assert result.error == "Empty file"
def test_oversized_file_returns_error():
    oversized_data = b"A" * (25 * 1024 * 1024 + 1)

    result = analyze_file_bytes(
        oversized_data,
        "large.txt",
        online=False,
    )

    assert result.error == (
        "File is larger than the 25 MB analysis limit"
    )
def test_file_extension_mismatch():
    fake_pdf = b"MZ" + b"\x00" * 200

    result = analyze_file_bytes(
        fake_pdf,
        "invoice.pdf",
        online=False,
    )

    ids = {signal.id for signal in result.signals}

    assert "file.mime_mismatch" in ids
    assert "file.executable" in ids
def test_windows_shortcut_detection():
    lnk_data = (
        b"L\x00\x00\x00\x01\x14\x02\x00"
        + b"\x00" * 100
    )

    result = analyze_file_bytes(
        lnk_data,
        "document.lnk",
        online=False,
    )

    ids = {signal.id for signal in result.signals}

    assert "file.lnk" in ids
def test_rtf_embedded_object_detection():
    rtf_data = (
        b"{\\rtf1\\ansi\n"
        b"Test document\n"
        b"\\objdata 41424344\n"
        b"}"
    )

    result = analyze_file_bytes(
        rtf_data,
        "document.rtf",
        online=False,
    )

    ids = {signal.id for signal in result.signals}

    assert "file.rtf_object" in ids
def test_internet_shortcut_detection():
    shortcut_data = (
        b"[InternetShortcut]\n"
        b"URL=https://example.com/login\n"
    )

    result = analyze_file_bytes(
        shortcut_data,
        "login.url",
        online=False,
    )

    ids = {signal.id for signal in result.signals}

    assert "file.url_shortcut" in ids
