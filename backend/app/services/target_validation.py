from __future__ import annotations

import ipaddress
import socket
from dataclasses import dataclass
from urllib.parse import urlsplit, urlunsplit


BLOCKED_SUFFIXES = (
    ".localhost", ".local", ".internal", ".test", ".invalid", ".example", ".onion",
)


class TargetValidationError(ValueError):
    """Raised when a scan target is unsafe or outside the supported scope."""


@dataclass(frozen=True)
class ValidatedTarget:
    url: str
    scheme: str
    hostname: str
    port: int
    resolved_addresses: tuple[str, ...]


def _is_public_address(value: str) -> bool:
    try:
        address = ipaddress.ip_address(value.split("%", 1)[0])
    except ValueError:
        return False

    # is_global excludes private, loopback, link-local, multicast,
    # unspecified, reserved and documentation ranges.
    if isinstance(address, ipaddress.IPv6Address) and address.ipv4_mapped:
        address = address.ipv4_mapped
    return address.is_global


def _resolve_public_addresses(hostname: str, port: int) -> tuple[str, ...]:
    try:
        records = socket.getaddrinfo(
            hostname, port, type=socket.SOCK_STREAM, proto=socket.IPPROTO_TCP
        )
    except socket.gaierror as exc:
        raise TargetValidationError("Não foi possível resolver o domínio informado.") from exc

    addresses = tuple(sorted({record[4][0].split("%", 1)[0] for record in records}))
    if not addresses:
        raise TargetValidationError("O domínio não retornou endereços IP.")
    if any(not _is_public_address(address) for address in addresses):
        raise TargetValidationError(
            "O domínio resolve para um endereço não público; o alvo foi bloqueado."
        )
    return addresses


def validate_target_url(
    value: str,
    *,
    resolver=_resolve_public_addresses,
) -> ValidatedTarget:
    """Validate an HTTP(S) target and resolve every address before scanning.

    A scanner must connect to one of the returned, validated addresses directly.
    It must not resolve the hostname again when opening the connection. Every
    redirect destination must pass this validation independently.
    """
    if not isinstance(value, str) or not value or len(value) > 2048:
        raise TargetValidationError("Informe uma URL válida de até 2048 caracteres.")

    try:
        parsed = urlsplit(value.strip())
        scheme = parsed.scheme.lower()
        if scheme not in {"http", "https"}:
            raise TargetValidationError("Somente URLs HTTP e HTTPS são permitidas.")
        if parsed.username is not None or parsed.password is not None:
            raise TargetValidationError("URLs com usuário ou senha embutidos não são permitidas.")
        if parsed.fragment:
            raise TargetValidationError("URLs com fragmentos não são aceitas.")
        hostname = parsed.hostname
        port = parsed.port
    except ValueError as exc:
        raise TargetValidationError("A URL informada está malformada.") from exc

    if not hostname:
        raise TargetValidationError("A URL precisa informar um domínio ou endereço IP.")

    try:
        hostname = hostname.rstrip(".").encode("idna").decode("ascii").lower()
    except UnicodeError as exc:
        raise TargetValidationError("O domínio informado contém caracteres inválidos.") from exc
    if not hostname or any(hostname.endswith(suffix) for suffix in BLOCKED_SUFFIXES):
        raise TargetValidationError("Domínios locais ou reservados não podem ser escaneados.")
    if "%" in hostname:
        raise TargetValidationError("Identificadores de zona IPv6 não são permitidos.")

    effective_port = port or (443 if scheme == "https" else 80)
    if effective_port not in {80, 443}:
        raise TargetValidationError("Somente as portas 80 e 443 são permitidas.")

    try:
        ipaddress.ip_address(hostname)
        is_ip_literal = True
    except ValueError:
        is_ip_literal = False

    if is_ip_literal:
        addresses = (hostname,)
        if not _is_public_address(hostname):
            raise TargetValidationError("Endereços IP não públicos não podem ser escaneados.")
    else:
        if "." not in hostname or hostname.startswith(".") or ".." in hostname:
            raise TargetValidationError("Informe um nome de domínio público válido.")
        addresses = tuple(sorted({str(address).split("%", 1)[0] for address in resolver(hostname, effective_port)}))
        if not addresses:
            raise TargetValidationError("O domínio não retornou endereços IP.")
        if any(not _is_public_address(address) for address in addresses):
            raise TargetValidationError(
                "O domínio resolve para um endereço não público; o alvo foi bloqueado."
            )

    netloc_host = f"[{hostname}]" if ":" in hostname else hostname
    netloc = netloc_host if (scheme, effective_port) in {("https", 443), ("http", 80)} else f"{netloc_host}:{effective_port}"
    normalized_url = urlunsplit((scheme, netloc, parsed.path or "/", parsed.query, ""))
    return ValidatedTarget(
        url=normalized_url,
        scheme=scheme,
        hostname=hostname,
        port=effective_port,
        resolved_addresses=addresses,
    )
