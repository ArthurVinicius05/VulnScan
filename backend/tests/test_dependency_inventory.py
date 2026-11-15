import io
import zipfile

from app.services.dependency_inventory import inventory_dependency_manifests


def make_zip(entries):
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w") as archive:
        for name, content in entries:
            archive.writestr(name, content)
    return buffer.getvalue()


def test_inventories_node_and_python_dependencies_without_network():
    data = make_zip([
        ("package.json", '{"dependencies":{"react":"^19"},"devDependencies":{"vite":"^6"}}'),
        ("requirements.txt", "fastapi>=0.1\n# comment\nhttpx>=0.2\n"),
    ])
    result = inventory_dependency_manifests(data)
    assert result["manifest_count"] == 2
    assert result["network_access"] is False
    assert result["packages_installed"] is False
    assert result["manifests"][0]["dependency_count"] == 2
    assert result["manifests"][1]["dependency_count"] == 2


def test_marks_invalid_package_json():
    result = inventory_dependency_manifests(make_zip([("package.json", "{bad json")]))
    assert result["manifests"][0]["status"] == "invalid_manifest"


def test_ignores_unsafe_paths():
    result = inventory_dependency_manifests(make_zip([("../package.json", '{"dependencies":{}}')]))
    assert result["manifest_count"] == 0
    assert result["skipped_unsafe_paths"] == 1
