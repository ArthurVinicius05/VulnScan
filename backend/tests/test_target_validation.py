import pytest

from app.services.target_validation import TargetValidationError, validate_target_url


def public_resolver(hostname, port):
    assert hostname == "example.org"
    assert port in (80, 443)
    return ("93.184.216.34",)


def test_accepts_public_https_domain_and_normalizes_url():
    target = validate_target_url("HTTPS://Example.ORG", resolver=public_resolver)
    assert target.url == "https://example.org/"
    assert target.hostname == "example.org"
    assert target.port == 443
    assert target.resolved_addresses == ("93.184.216.34",)


@pytest.mark.parametrize("url", [
    "file:///etc/passwd",
    "ftp://example.org",
    "http://user:pass@example.org",
    "http://127.0.0.1",
    "http://10.0.0.1",
    "http://169.254.169.254/latest/meta-data",
    "http://[::1]",
    "http://localhost",
    "http://service.internal",
    "http://example.org:8080",
    "http://example.org#fragment",
])
def test_rejects_unsafe_or_unsupported_targets(url):
    with pytest.raises(TargetValidationError):
        validate_target_url(url, resolver=public_resolver)


def test_rejects_domain_if_any_dns_answer_is_private():
    def mixed_resolver(hostname, port):
        return ("93.184.216.34", "192.168.1.10")

    with pytest.raises(TargetValidationError, match="não público"):
        validate_target_url("https://example.org", resolver=mixed_resolver)


def test_rejects_empty_dns_answers():
    with pytest.raises(TargetValidationError, match="não retornou"):
        validate_target_url("https://example.org", resolver=lambda *_: ())


def test_rejects_invalid_dns_resolution():
    def failed_resolver(*_):
        raise TargetValidationError("DNS indisponível")

    with pytest.raises(TargetValidationError):
        validate_target_url("https://example.org", resolver=failed_resolver)


def test_rejects_invalid_idna_hostname():
    with pytest.raises(TargetValidationError, match="caracteres inválidos"):
        validate_target_url("https://\ud800.example.org", resolver=public_resolver)
