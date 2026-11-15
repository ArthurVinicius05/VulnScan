import io
import zipfile

import pytest

from app.services.zip_inspector import inspect_zip


def make_zip(entries):
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w") as archive:
        for name, content in entries:
            archive.writestr(name, content)
    return buffer.getvalue()


def test_detects_python_project():
    data = make_zip([("app.py", "print('hello')"), ("requirements.txt", "fastapi")])
    result = inspect_zip(data, max_files=20, max_uncompressed_bytes=10000)
    assert "Python" in result["detected_technologies"]
    assert result["file_count"] == 2


def test_rejects_path_traversal():
    data = make_zip([("../outside.txt", "bad")])
    with pytest.raises(ValueError, match="path traversal"):
        inspect_zip(data, max_files=20, max_uncompressed_bytes=10000)


def test_rejects_too_many_files():
    data = make_zip([(f"{i}.txt", "x") for i in range(3)])
    with pytest.raises(ValueError, match="arquivos demais"):
        inspect_zip(data, max_files=2, max_uncompressed_bytes=10000)
