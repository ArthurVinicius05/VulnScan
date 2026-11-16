from app.middleware.upload_auth import UploadAuthenticationMiddleware


class _Query:
    def filter(self, *_args, **_kwargs):
        return self

    def first(self):
        return None


class _Database:
    def query(self, *_args, **_kwargs):
        return _Query()

    def close(self):
        pass


def test_upload_middleware_rejects_non_ascii_csrf_without_server_error(monkeypatch):
    monkeypatch.setattr(
        "app.middleware.upload_auth.SessionLocal",
        lambda: _Database(),
    )
    scope = {
        "headers": [
            (b"origin", b"http://localhost:5173"),
            (b"cookie", b"vulnscan_session=valid; vulnscan_csrf=\xe9"),
            (b"x-csrf-token", b"\xe9"),
        ]
    }

    authenticated, status_code, detail = UploadAuthenticationMiddleware._authenticated(scope)

    assert authenticated is False
    assert status_code == 401
    assert detail == "Sessão inválida ou encerrada."
