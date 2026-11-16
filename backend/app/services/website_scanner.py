from __future__ import annotations

import http.client
import socket
import ssl
from dataclasses import dataclass
from urllib.parse import urljoin, urlsplit

from app.services.target_validation import (
    TargetValidationError,
    ValidatedTarget,
    validate_target_url,
)

MAX_REDIRECTS = 3
MAX_BODY_BYTES = 64 * 1024
REQUEST_TIMEOUT_SECONDS = 8.0
SECURITY_HEADERS = {
    "strict-transport-security": (
        "high", "HTTPS responses should use Strict-Transport-Security."
    ),
    "content-security-policy": (
        "medium", "A Content-Security-Policy header helps mitigate content injection."
    ),
    "x-content-type-options": (
        "low", "Set X-Content-Type-Options: nosniff."
    ),
    "referrer-policy": (
        "low", "Set an explicit Referrer-Policy."
    ),
    "permissions-policy": (
        "informational", "Consider restricting browser features with Permissions-Policy."
    ),
}


@dataclass(frozen=True)
class HTTPResult:
    status: int
    headers: tuple[tuple[str, str], ...]
    body_sample: bytes
    tls_version: str | None = None
    certificate_expiry: str | None = None


class PinnedHTTPConnection(http.client.HTTPConnection):
    """HTTP connection that dials only a previously validated IP address."""

    def __init__(self, target: ValidatedTarget, address: str, timeout: float):
        super().__init__(target.hostname, target.port, timeout=timeout)
        self.target = target
        self.address = address

    def connect(self):
        raw = socket.create_connection(
            (self.address, self.target.port), timeout=self.timeout
        )
        if self.target.scheme == "https":
            context = ssl.create_default_context()
            self.sock = context.wrap_socket(raw, server_hostname=self.target.hostname)
        else:
            self.sock = raw


def _host_header(target: ValidatedTarget) -> str:
    host = f"[{target.hostname}]" if ":" in target.hostname else target.hostname
    default_port = 443 if target.scheme == "https" else 80
    return host if target.port == default_port else f"{host}:{target.port}"


def _request_once(target: ValidatedTarget) -> HTTPResult:
    last_error = None
    for address in target.resolved_addresses:
        connection = PinnedHTTPConnection(
            target, address, REQUEST_TIMEOUT_SECONDS
        )
        try:
            parsed = urlsplit(target.url)
            path = parsed.path or "/"
            if parsed.query:
                path += "?" + parsed.query
            connection.request(
                "GET",
                path,
                headers={
                    "Host": _host_header(target),
                    "User-Agent": "VulnScan/0.4 (authorized passive audit)",
                    "Accept": "*/*",
                    "Connection": "close",
                },
            )
            response = connection.getresponse()
            body = response.read(MAX_BODY_BYTES + 1)
            if len(body) > MAX_BODY_BYTES:
                body = body[:MAX_BODY_BYTES]
            tls_version = None
            cert_expiry = None
            if connection.sock and target.scheme == "https":
                tls_version = connection.sock.version()
                cert = connection.sock.getpeercert()
                cert_expiry = cert.get("notAfter")
            return HTTPResult(
                status=response.status,
                headers=tuple(response.getheaders()),
                body_sample=body,
                tls_version=tls_version,
                certificate_expiry=cert_expiry,
            )
        except (OSError, ssl.SSLError, http.client.HTTPException) as exc:
            last_error = exc
        finally:
            connection.close()
    raise RuntimeError(f"Não foi possível conectar ao alvo validado: {last_error}")


def _header_findings(target: ValidatedTarget, result: HTTPResult) -> list[dict]:
    headers = {key.lower(): value for key, value in result.headers}
    findings = []
    if target.scheme == "https" and "strict-transport-security" not in headers:
        findings.append({
            "rule_id": "WEB-HDR-001",
            "severity": "high",
            "title": "HSTS ausente",
            "evidence": "A resposta HTTPS não apresentou Strict-Transport-Security.",
            "remediation": SECURITY_HEADERS["strict-transport-security"][1],
        })
    for name, (severity, remediation) in SECURITY_HEADERS.items():
        if name == "strict-transport-security" and target.scheme == "https":
            continue
        if name not in headers:
            findings.append({
                "rule_id": "WEB-HDR-" + name.upper().replace("-", ""),
                "severity": severity,
                "title": f"Cabeçalho {name} ausente",
                "evidence": f"A resposta não apresentou o cabeçalho {name}.",
                "remediation": remediation,
            })

    cookie_headers = [
        value for key, value in result.headers if key.lower() == "set-cookie"
    ]
    for index, cookie in enumerate(cookie_headers, start=1):
        lower = cookie.lower()
        for attribute, severity in (
            ("secure", "medium" if target.scheme == "https" else "informational"),
            ("httponly", "medium"),
            ("samesite", "low"),
        ):
            if attribute not in lower:
                findings.append({
                    "rule_id": f"WEB-COOKIE-{attribute.upper()}",
                    "severity": severity,
                    "title": f"Cookie sem atributo {attribute.capitalize()}",
                    "evidence": f"Cookie de resposta #{index} não declara {attribute.capitalize()}.",
                    "remediation": f"Revise se o cookie deve incluir o atributo {attribute.capitalize()}.",
                })
    return findings


def scan_website(
    url: str,
    *,
    validator=validate_target_url,
    requester=_request_once,
) -> dict:
    """Perform a bounded passive GET scan; redirects are revalidated and pinned."""
    current_url = url
    visited: set[str] = set()
    redirect_chain: list[str] = []

    for redirect_count in range(MAX_REDIRECTS + 1):
        target = validator(current_url)
        if target.url in visited:
            raise TargetValidationError("Ciclo de redirecionamento detectado.")
        visited.add(target.url)
        result = requester(target)
        headers = {key.lower(): value for key, value in result.headers}

        if result.status in {301, 302, 303, 307, 308} and "location" in headers:
            if redirect_count >= MAX_REDIRECTS:
                raise TargetValidationError("Limite de redirecionamentos excedido.")
            next_url = urljoin(target.url, headers["location"])
            # Validate before following; the next loop repeats validation immediately
            # before connection, and the requester connects only to pinned IPs.
            validator(next_url)
            redirect_chain.append(target.url)
            current_url = next_url
            continue

        findings = _header_findings(target, result)
        return {
            "status": "completed",
            "scan_type": "passive_http_headers",
            "target": target.url,
            "http_status": result.status,
            "redirect_chain": redirect_chain,
            "tls": {
                "version": result.tls_version,
                "certificate_expiry": result.certificate_expiry,
            } if target.scheme == "https" else None,
            "response_body_sampled": bool(result.body_sample),
            "response_body_bytes_sampled": len(result.body_sample),
            "finding_count": len(findings),
            "findings": findings,
            "notice": (
                "Verificação passiva limitada à resposta HTTP inicial; "
                "não executa payloads, fuzzing ou testes de exploração."
            ),
        }

    raise TargetValidationError("Limite de redirecionamentos excedido.")
