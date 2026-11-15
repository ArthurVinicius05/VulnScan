import socket
import pytest

from app.smtp_proxy import resolve_upstream, validate_public_ip


@pytest.mark.parametrize("address", ["127.0.0.1", "10.0.0.1", "169.254.169.254", "::1", "fc00::1"])
def test_smtp_proxy_rejects_non_public_upstream_addresses(address):
    with pytest.raises(RuntimeError, match="non-public"):
        validate_public_ip(address)


@pytest.mark.parametrize("address", ["8.8.8.8", "1.1.1.1", "2606:4700:4700::1111"])
def test_smtp_proxy_accepts_public_upstream_addresses(address):
    assert validate_public_ip(address) == address


def test_smtp_proxy_rejects_implicit_tls_and_unexpected_ports():
    with pytest.raises(RuntimeError, match="STARTTLS ports"):
        resolve_upstream("mail.provider.example", 465)


def test_smtp_proxy_pins_resolved_public_addresses(monkeypatch):
    monkeypatch.setattr(socket, "getaddrinfo", lambda *args, **kwargs: [
        (socket.AF_INET, socket.SOCK_STREAM, socket.IPPROTO_TCP, "", ("8.8.8.8", 587)),
        (socket.AF_INET, socket.SOCK_STREAM, socket.IPPROTO_TCP, "", ("1.1.1.1", 587)),
    ])
    assert resolve_upstream("mail.provider.example", 587) == ["1.1.1.1", "8.8.8.8"]
