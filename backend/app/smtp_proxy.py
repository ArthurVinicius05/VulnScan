from __future__ import annotations

import asyncio
import ipaddress
import logging
import os
import socket
from typing import Iterable

logger = logging.getLogger("vulnscan.smtp_proxy")
LISTEN_HOST = "0.0.0.0"
LISTEN_PORT = 2525
BUFFER_SIZE = 64 * 1024


def validate_public_ip(raw_ip: str) -> str:
    address = ipaddress.ip_address(raw_ip)
    if not address.is_global:
        raise RuntimeError("SMTP upstream resolved to a non-public IP address; refusing to start.")
    return str(address)


def resolve_upstream(host: str, port: int) -> list[str]:
    if port not in (25, 587, 2525):
        raise RuntimeError("SMTP proxy only permits STARTTLS ports 25, 587 or 2525.")
    if not host or host in {"localhost", "smtp-proxy"}:
        raise RuntimeError("SMTP_UPSTREAM_HOST must be a real upstream hostname.")
    records = socket.getaddrinfo(host, port, type=socket.SOCK_STREAM)
    addresses = sorted({validate_public_ip(record[4][0]) for record in records})
    if not addresses:
        raise RuntimeError("SMTP upstream did not resolve to a public IP address.")
    return addresses


async def _pipe(reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
    try:
        while data := await reader.read(BUFFER_SIZE):
            writer.write(data)
            await writer.drain()
    finally:
        if writer.can_write_eof():
            writer.write_eof()


async def relay_client(
    client_reader: asyncio.StreamReader,
    client_writer: asyncio.StreamWriter,
    upstream_addresses: list[str],
    upstream_port: int,
    semaphore: asyncio.Semaphore,
) -> None:
    upstream_writer: asyncio.StreamWriter | None = None
    peer = client_writer.get_extra_info("peername")
    if semaphore.locked():
        client_writer.close()
        await client_writer.wait_closed()
        return
    try:
        async with semaphore:
            for address in upstream_addresses:
                try:
                    upstream_reader, upstream_writer = await asyncio.wait_for(
                        asyncio.open_connection(address, upstream_port), timeout=8
                    )
                    break
                except (OSError, asyncio.TimeoutError):
                    upstream_writer = None
            else:
                return
            await asyncio.gather(
                _pipe(client_reader, upstream_writer),
                _pipe(upstream_reader, client_writer),
            )
    except (ConnectionError, asyncio.CancelledError):
        raise
    except Exception as exc:
        logger.warning("SMTP relay connection failed for %s: %s", peer, type(exc).__name__)
    finally:
        if upstream_writer is not None:
            upstream_writer.close()
            try:
                await upstream_writer.wait_closed()
            except OSError:
                pass
        client_writer.close()
        try:
            await client_writer.wait_closed()
        except OSError:
            pass


async def serve() -> None:
    upstream_host = os.environ.get("SMTP_UPSTREAM_HOST", "").strip()
    upstream_port = int(os.environ.get("SMTP_UPSTREAM_PORT", "587"))
    max_connections = int(os.environ.get("SMTP_PROXY_MAX_CONNECTIONS", "20"))
    if not 1 <= upstream_port <= 65535 or not 1 <= max_connections <= 100:
        raise RuntimeError("Invalid SMTP proxy port or connection limit.")
    addresses = resolve_upstream(upstream_host, upstream_port)
    semaphore = asyncio.Semaphore(max_connections)
    logger.info("SMTP proxy restricted to %s:%s (%s)", upstream_host, upstream_port, ", ".join(addresses))
    server = await asyncio.start_server(
        lambda reader, writer: relay_client(reader, writer, addresses, upstream_port, semaphore),
        LISTEN_HOST,
        LISTEN_PORT,
        limit=BUFFER_SIZE,
    )
    async with server:
        await server.serve_forever()


if __name__ == "__main__":
    logging.basicConfig(level=os.environ.get("LOG_LEVEL", "INFO"))
    asyncio.run(serve())
