import io
import zipfile

from app.services.scanner_integrations import run_python_tools


def make_zip(entries):
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w") as archive:
        for name, content in entries:
            archive.writestr(name, content)
    return buffer.getvalue()


def test_skips_when_archive_has_no_python_files():
    result = run_python_tools(make_zip([("README.md", "# project")]))
    assert result["status"] == "skipped"
    assert result["findings"] == []


def test_ignores_unsafe_python_paths():
    result = run_python_tools(make_zip([("../outside.py", "print('no')")]))
    assert result["status"] == "skipped"
