"""
utils.py — Utility functions and constants for Mini Network Scanner.
"""

import ipaddress
import logging
import re
import socket
from datetime import datetime
from typing import List, Tuple, Optional


# ─── Colour palette (shared with GUI) ────────────────────────────────────────
COLORS = {
    "bg":       "#0d1117",
    "panel":    "#161b22",
    "border":   "#30363d",
    "accent":   "#00d4aa",
    "accent2":  "#58a6ff",
    "danger":   "#f85149",
    "warning":  "#e3b341",
    "success":  "#3fb950",
    "text":     "#e6edf3",
    "muted":    "#8b949e",
}

# ─── Common service name map ──────────────────────────────────────────────────
SERVICE_MAP = {
    21:   "FTP",
    22:   "SSH",
    23:   "Telnet",
    25:   "SMTP",
    53:   "DNS",
    80:   "HTTP",
    110:  "POP3",
    143:  "IMAP",
    443:  "HTTPS",
    445:  "SMB",
    3306: "MySQL",
    3389: "RDP",
    5432: "PostgreSQL",
    5900: "VNC",
    6379: "Redis",
    8080: "HTTP-Alt",
    8443: "HTTPS-Alt",
    9200: "Elasticsearch",
    27017:"MongoDB",
}

# ─── Logging setup ────────────────────────────────────────────────────────────

def setup_logger(name: str = "netscan", level: int = logging.DEBUG) -> logging.Logger:
    """Create and return a named logger with console + optional file handler."""
    logger = logging.getLogger(name)
    if logger.handlers:
        return logger
    logger.setLevel(level)

    fmt = logging.Formatter(
        "[%(asctime)s] %(levelname)-8s %(message)s",
        datefmt="%H:%M:%S",
    )

    ch = logging.StreamHandler()
    ch.setLevel(level)
    ch.setFormatter(fmt)
    logger.addHandler(ch)

    return logger


# ─── IP / CIDR helpers ────────────────────────────────────────────────────────

def parse_targets(target_str: str) -> List[str]:
    """
    Parse a target string into a flat list of IP address strings.

    Accepts:
      - Single IP:        192.168.1.1
      - CIDR range:       192.168.1.0/24
      - Dash range:       192.168.1.1-192.168.1.50
      - Hostname:         example.com
    """
    target_str = target_str.strip()
    ips: List[str] = []

    # CIDR notation
    if "/" in target_str:
        try:
            network = ipaddress.IPv4Network(target_str, strict=False)
            ips = [str(h) for h in network.hosts()]
            return ips
        except ValueError as exc:
            raise ValueError(f"Invalid CIDR: {target_str}") from exc

    # Dash-range  (e.g. 10.0.0.1-10.0.0.20)
    if "-" in target_str:
        parts = target_str.split("-")
        if len(parts) == 2:
            try:
                start = int(ipaddress.IPv4Address(parts[0].strip()))
                end   = int(ipaddress.IPv4Address(parts[1].strip()))
                if start > end:
                    raise ValueError("Start address must be ≤ end address.")
                ips = [str(ipaddress.IPv4Address(i)) for i in range(start, end + 1)]
                return ips
            except Exception as exc:
                raise ValueError(f"Invalid IP range: {target_str}") from exc

    # Single IP or hostname
    try:
        ipaddress.IPv4Address(target_str)
        return [target_str]
    except ValueError:
        pass

    # Attempt DNS resolution for hostnames
    try:
        resolved = socket.gethostbyname(target_str)
        return [resolved]
    except socket.gaierror as exc:
        raise ValueError(f"Cannot resolve hostname: {target_str}") from exc


def parse_port_range(port_str: str) -> List[int]:
    """
    Parse a port range string into a list of port integers.

    Accepts:
      - Single port:   80
      - Comma list:    22,80,443
      - Range:         1-1024
      - Mixed:         22,80,443,8000-8100
    """
    ports: List[int] = []
    for part in port_str.split(","):
        part = part.strip()
        if "-" in part:
            lo, hi = part.split("-", 1)
            lo, hi = int(lo.strip()), int(hi.strip())
            ports.extend(range(lo, hi + 1))
        else:
            ports.append(int(part))
    ports = sorted(set(ports))
    # validate
    for p in ports:
        if not (1 <= p <= 65535):
            raise ValueError(f"Port {p} out of valid range (1-65535).")
    return ports


def guess_service(port: int) -> str:
    """Return a human-readable service name for a known port, or 'Unknown'."""
    return SERVICE_MAP.get(port, "Unknown")


def timestamp() -> str:
    """Return the current UTC timestamp as an ISO-8601 string."""
    return datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%SZ")


def format_duration(seconds: float) -> str:
    """Format a duration in seconds into a human-readable string."""
    if seconds < 60:
        return f"{seconds:.2f}s"
    mins = int(seconds // 60)
    secs = seconds % 60
    return f"{mins}m {secs:.1f}s"
