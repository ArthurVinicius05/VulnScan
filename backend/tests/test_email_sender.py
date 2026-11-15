from app.core.config import settings
from app.services import email_sender


class FakeSMTP:
    instance = None

    def __init__(self, host, port, timeout):
        self.host = host
        self.port = port
        self.timeout = timeout
        self._host = host
        self.tls_server_name = None
        FakeSMTP.instance = self

    def __enter__(self): return self
    def __exit__(self, *args): return False
    def starttls(self, context):
        self.tls_server_name = self._host
        assert context is not None
    def login(self, username, password): pass
    def send_message(self, message): pass


def test_smtp_proxy_connection_validates_upstream_tls_hostname(monkeypatch):
    monkeypatch.setattr(settings, "smtp_host", "smtp-proxy")
    monkeypatch.setattr(settings, "smtp_port", 2525)
    monkeypatch.setattr(settings, "smtp_tls_server_name", "mail.provider.example")
    monkeypatch.setattr(settings, "smtp_starttls", True)
    monkeypatch.setattr(settings, "smtp_username", None)
    monkeypatch.setattr(settings, "mail_from", "noreply@example.test")
    monkeypatch.setattr(email_sender.smtplib, "SMTP", FakeSMTP)

    email_sender.send_account_email("user@example.test", "Subject", "Body")

    assert FakeSMTP.instance.host == "smtp-proxy"
    assert FakeSMTP.instance.tls_server_name == "mail.provider.example"
