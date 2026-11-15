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


def test_marks_python_tools_partial_when_archive_exceeds_file_cap(monkeypatch):
    import app.services.scanner_integrations as integrations

    data = make_zip([(f"src/file_{index}.py", "print('ok')") for index in range(51)])
    monkeypatch.setattr(integrations, "_run_json_tool", lambda *args, **kwargs: ("completed", {"results": []} if "bandit" in args[0][2] else []))
    monkeypatch.setattr(integrations.shutil, "which", lambda name: "/usr/bin/ruff")

    result = run_python_tools(data)

    assert result["status"] == "partial"
    assert result["coverage"]["python_files_available"] == 51
    assert result["coverage"]["python_files_scanned"] == 50
    assert result["coverage"]["truncated"] is True
    assert all(tool["status"] == "partial" for tool in result["tools"])
