
import pytest

from app.services.target_validation import TargetValidationError, ValidatedTarget
from app.services.website_scanner import HTTPResult, _host_header, scan_website


def target(url):
    return ValidatedTarget(
        url=url, scheme="https", hostname="example.org", port=443,
        resolved_addresses=("93.184.216.34",),
    )


def test_passive_scan_reports_missing_headers_without_exploitation():
    calls = []

    def requester(validated):
        calls.append(validated.url)
        return HTTPResult(
            status=200,
            headers=(("Content-Type", "text/html"),),
            body_sample=b"<html>sample</html>",
            tls_version="TLSv1.3",
        )

    result = scan_website(
        "https://example.org",
        validator=lambda value: target(value.rstrip("/") if value.endswith("/") else value),
        requester=requester,
    )
    assert result["status"] == "completed"
    assert result["scan_type"] == "passive_http_headers"
    assert result["http_status"] == 200
    assert result["tls"]["version"] == "TLSv1.3"
    assert result["finding_count"] > 0
    assert len(calls) == 1


def test_redirect_is_revalidated_before_request():
    seen = []

    def validator(value):
        seen.append(value)
        if "169.254.169.254" in value:
            raise TargetValidationError("IP não público")
        return target(value)

    responses = iter([
        HTTPResult(302, (("Location", "http://169.254.169.254/latest/meta-data"),), b""),
    ])

    with pytest.raises(TargetValidationError, match="não público"):
        scan_website("https://example.org", validator=validator, requester=lambda _: next(responses))
    assert len(seen) == 2


def test_redirect_loop_is_rejected():
    def requester(_):
        return HTTPResult(302, (("Location", "https://example.org"),), b"")

    with pytest.raises(TargetValidationError, match="Ciclo"):
        scan_website("https://example.org", validator=target, requester=requester)


def test_cookie_flags_are_reported():
    from app.services.website_scanner import _header_findings

    result = HTTPResult(
        200, (("Set-Cookie", "session=abc; Path=/"),), b""
    )
    findings = _header_findings(target("https://example.org"), result)
    rules = {finding["rule_id"] for finding in findings}
    assert "WEB-COOKIE-SECURE" in rules
    assert "WEB-COOKIE-HTTPONLY" in rules
    assert "WEB-COOKIE-SAMESITE" in rules


@pytest.mark.parametrize(
    ("scheme", "port", "expected"),
    [("https", 443, "example.org"), ("https", 80, "example.org:80"),
     ("http", 80, "example.org"), ("http", 443, "example.org:443")],
)
def test_host_header_uses_scheme_default_port(scheme, port, expected):
    validated = ValidatedTarget(
        url=f"{scheme}://example.org:{port}/", scheme=scheme,
        hostname="example.org", port=port, resolved_addresses=("93.184.216.34",),
    )
    assert _host_header(validated) == expected
