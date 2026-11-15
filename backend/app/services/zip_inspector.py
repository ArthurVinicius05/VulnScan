from __future__ import annotations

import io
import re
import zipfile
from pathlib import PurePosixPath

KNOWN_MARKERS = {
    "package.json": "Node.js",
    "pnpm-lock.yaml": "Node.js / pnpm",
    "yarn.lock": "Node.js / Yarn",
    "package-lock.json": "Node.js / npm",
    "requirements.txt": "Python",
    "pyproject.toml": "Python",
    "Pipfile": "Python",
    "Cargo.toml": "Rust",
    "go.mod": "Go",
    "pom.xml": "Java / Maven",
    "build.gradle": "Java / Gradle",
    "composer.json": "PHP / Composer",
    "Gemfile": "Ruby",
    "Dockerfile": "Docker",
    "manage.py": "Django (possible)",
    "artisan": "Laravel (possible)",
}


def _safe_member_name(name: str) -> bool:
    if not name or "\\" in name or name.startswith(("/", "\\")):
        return False
    if re.match(r"^[A-Za-z]:", name):
        return False
    return not any(part in ("..", "") for part in PurePosixPath(name).parts)


def inspect_zip(data: bytes, *, max_files: int, max_uncompressed_bytes: int) -> dict:
    try:
        archive = zipfile.ZipFile(io.BytesIO(data))
    except (zipfile.BadZipFile, OSError) as exc:
        raise ValueError("Arquivo ZIP inválido ou corrompido.") from exc

    with archive:
        infos = archive.infolist()
        if len(infos) > max_files:
            raise ValueError(f"ZIP contém arquivos demais (limite: {max_files}).")

        total_size = 0
        paths = []
        markers = set()

        for info in infos:
            if not _safe_member_name(info.filename):
                raise ValueError("ZIP contém caminho absoluto ou tentativa de path traversal.")

            unix_mode = (info.external_attr >> 16) & 0xFFFF
            file_type = unix_mode & 0o170000
            if file_type not in (0, 0o100000, 0o040000):
                raise ValueError("ZIP contém link simbólico ou arquivo especial.")
            if info.flag_bits & 0x1:
                raise ValueError("ZIP criptografado não é aceito.")

            total_size += info.file_size
            if total_size > max_uncompressed_bytes:
                raise ValueError("Conteúdo descompactado excede o limite permitido.")
            if info.file_size and info.compress_size == 0:
                raise ValueError("ZIP contém entrada com tamanho compactado suspeito.")
            if info.compress_size and info.file_size / info.compress_size > 200:
                raise ValueError("ZIP apresenta taxa de expansão suspeita.")

            if info.is_dir():
                continue
            paths.append(info.filename)
            marker = PurePosixPath(info.filename).name
            if marker in KNOWN_MARKERS:
                markers.add(KNOWN_MARKERS[marker])

        return {
            "file_count": len(paths),
            "total_uncompressed_bytes": total_size,
            "detected_technologies": sorted(markers),
            "sample_paths": sorted(paths)[:80],
        }
