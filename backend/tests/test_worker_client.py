import asyncio

import httpx

from app.services.worker_client import scan_python_archive


def test_worker_client_returns_unavailable_when_worker_is_down(monkeypatch):
    class BrokenClient:
        def __init__(self, *args, **kwargs):
            pass

        async def __aenter__(self):
            return self

        async def __aexit__(self, *args):
            return False

        async def post(self, *args, **kwargs):
            raise httpx.ConnectError("worker offline")

    monkeypatch.setattr("app.services.worker_client.httpx.AsyncClient", BrokenClient)
    result = asyncio.run(scan_python_archive(b"archive"))
    assert result["status"] == "unavailable"
    assert result["findings"] == []
