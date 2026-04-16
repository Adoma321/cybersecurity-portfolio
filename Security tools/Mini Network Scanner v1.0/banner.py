"""
banner.py — Banner grabbing and service fingerprinting.
"""

import socket
import ssl
from typing import Optional
from utils import guess_service, setup_logger

logger = setup_logger("banner")

# Probes to send for specific ports to elicit a banner
_PROBES: dict[int, bytes] = {
    80:   b"HEAD / HTTP/1.0\r\nHost: target\r\n\r\n",
    443:  b"HEAD / HTTP/1.0\r\nHost: target\r\n\r\n",
    8080: b"HEAD / HTTP/1.0\r\nHost: target\r\n\r\n",
    8443: b"HEAD / HTTP/1.0\r\nHost: target\r\n\r\n",
    21:   None,   # FTP server sends banner on connect — no probe needed
    22:   None,   # SSH idem
    25:   None,   # SMTP idem
    110:  None,
    143:  None,
    23:   b"\r\n",
}

_READ_SIZE   = 1024
_RECV_TRIES  = 3


def grab_banner(host: str, port: int, timeout: float = 2.0) -> Optional[str]:
    """
    Attempt to grab the service banner from *host*:*port*.

    Returns the banner string (stripped), or None on failure.
    """
    raw: Optional[bytes] = None

    # HTTPS / TLS-wrapped ports
    if port in (443, 8443):
        raw = _grab_tls(host, port, timeout)
    else:
        raw = _grab_plain(host, port, timeout)

    if raw:
        banner = _clean_banner(raw)
        if banner:
            logger.debug("Banner [%s:%d] → %s", host, port, banner[:80])
            return banner

    return None


# ─── Internal helpers ─────────────────────────────────────────────────────────

def _grab_plain(host: str, port: int, timeout: float) -> Optional[bytes]:
    """Connect via plain TCP and attempt to read a banner."""
    try:
        with socket.create_connection((host, port), timeout=timeout) as sock:
            sock.settimeout(timeout)
            probe = _PROBES.get(port, None)
            if probe:
                sock.sendall(probe)
            data = b""
            for _ in range(_RECV_TRIES):
                try:
                    chunk = sock.recv(_READ_SIZE)
                    if not chunk:
                        break
                    data += chunk
                    if len(data) >= _READ_SIZE:
                        break
                except socket.timeout:
                    break
            return data or None
    except (OSError, ConnectionRefusedError, socket.timeout):
        return None


def _grab_tls(host: str, port: int, timeout: float) -> Optional[bytes]:
    """Connect via TLS and attempt to read a banner."""
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode    = ssl.CERT_NONE
    try:
        with socket.create_connection((host, port), timeout=timeout) as raw_sock:
            with ctx.wrap_socket(raw_sock, server_hostname=host) as sock:
                sock.settimeout(timeout)
                probe = _PROBES.get(port, None)
                if probe:
                    sock.sendall(probe)
                data = b""
                for _ in range(_RECV_TRIES):
                    try:
                        chunk = sock.recv(_READ_SIZE)
                        if not chunk:
                            break
                        data += chunk
                        if len(data) >= _READ_SIZE:
                            break
                    except socket.timeout:
                        break
                return data or None
    except Exception:
        return None


def _clean_banner(raw: bytes) -> Optional[str]:
    """Decode raw bytes into a printable one-liner banner string."""
    try:
        text = raw.decode("utf-8", errors="replace")
    except Exception:
        text = raw.decode("latin-1", errors="replace")

    lines = [l.strip() for l in text.splitlines() if l.strip()]
    if not lines:
        return None
    # Return first 2 meaningful lines joined
    snippet = " | ".join(lines[:2])
    # Clip to 200 chars
    return snippet[:200] if snippet else None


def identify_service(port: int, banner: Optional[str]) -> str:
    """
    Try to identify the service name from the port number and banner text.
    Falls back to the SERVICE_MAP lookup in utils.
    """
    name = guess_service(port)

    if banner:
        b = banner.lower()
        if "ssh"        in b: return "SSH"
        if "ftp"        in b: return "FTP"
        if "smtp"       in b: return "SMTP"
        if "pop3"       in b or "+ok" in b: return "POP3"
        if "imap"       in b: return "IMAP"
        if "http"       in b: return "HTTP" if port != 443 else "HTTPS"
        if "mysql"      in b: return "MySQL"
        if "postgresql" in b or "postgres" in b: return "PostgreSQL"
        if "redis"      in b: return "Redis"
        if "mongodb"    in b: return "MongoDB"
        if "vnc"        in b: return "VNC"

    return name
