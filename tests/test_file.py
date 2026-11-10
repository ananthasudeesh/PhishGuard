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
