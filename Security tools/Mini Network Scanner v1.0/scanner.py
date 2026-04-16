"""
scanner.py — Host discovery (ICMP/socket) and multithreaded port scanning engine.
"""

import socket
import subprocess
import platform
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field
from threading import Event
from typing import Callable, Dict, List, Optional

from banner import grab_banner, identify_service
from utils import guess_service, setup_logger, timestamp

logger = setup_logger("scanner")

# ─── Data structures ──────────────────────────────────────────────────────────

@dataclass
class PortResult:
    port:    int
    state:   str          # "open" | "closed" | "filtered"
    service: str
    banner:  Optional[str] = None


@dataclass
class HostResult:
    ip:         str
    status:     str = "down"           # "up" | "down"
    hostname:   Optional[str] = None
    ports:      List[PortResult] = field(default_factory=list)
    scan_time:  float = 0.0
    scanned_at: str = field(default_factory=timestamp)

    @property
    def open_ports(self) -> List[PortResult]:
        return [p for p in self.ports if p.state == "open"]


# ─── Scanner class ────────────────────────────────────────────────────────────

class NetworkScanner:
    """
    Thread-safe network scanner supporting:
      - ICMP ping-based host discovery (falls back to TCP if ping fails)
      - TCP connect port scanning
      - Banner grabbing on open ports
    """

    def __init__(
        self,
        timeout:        float = 1.0,
        max_workers:    int   = 100,
        grab_banners:   bool  = True,
        stop_event:     Optional[Event] = None,
        progress_cb:    Optional[Callable[[int, int], None]] = None,
        result_cb:      Optional[Callable[[HostResult], None]] = None,
        log_cb:         Optional[Callable[[str], None]] = None,
    ):
        self.timeout      = timeout
        self.max_workers  = max_workers
        self.grab_banners = grab_banners
        self.stop_event   = stop_event or Event()
        self.progress_cb  = progress_cb   # (done, total)
        self.result_cb    = result_cb     # called for each completed host
        self.log_cb       = log_cb        # log message callback

    # ─── Public API ───────────────────────────────────────────────────────────

    def scan(self, hosts: List[str], ports: List[int]) -> List[HostResult]:
        """
        Scan all *hosts* for *ports*.

        Returns a list of HostResult objects.
        """
        results: List[HostResult] = []
        total   = len(hosts)
        done    = 0

        self._log(f"Starting scan: {total} host(s), {len(ports)} port(s)")

        with ThreadPoolExecutor(max_workers=min(self.max_workers, total or 1)) as ex:
            futures = {ex.submit(self._scan_host, ip, ports): ip for ip in hosts}

            for fut in as_completed(futures):
                if self.stop_event.is_set():
                    self._log("Scan stopped by user.")
                    break

                try:
                    result = fut.result()
                    results.append(result)
                    if self.result_cb:
                        self.result_cb(result)
                except Exception as exc:
                    ip = futures[fut]
                    logger.error("Error scanning %s: %s", ip, exc)
                    self._log(f"[ERROR] {ip}: {exc}")
                finally:
                    done += 1
                    if self.progress_cb:
                        self.progress_cb(done, total)

        self._log(f"Scan complete. {len(results)} result(s) collected.")
        return results

    # ─── Host-level scan ──────────────────────────────────────────────────────

    def _scan_host(self, ip: str, ports: List[int]) -> HostResult:
        t0     = time.perf_counter()
        result = HostResult(ip=ip)

        # Resolve hostname
        try:
            result.hostname = socket.gethostbyaddr(ip)[0]
        except Exception:
            result.hostname = None

        # Host discovery
        if self._is_alive(ip):
            result.status = "up"
            self._log(f"[UP]   {ip}" + (f" ({result.hostname})" if result.hostname else ""))

            # Port scan
            open_ports = self._scan_ports(ip, ports)
            result.ports = open_ports

            if open_ports:
                self._log(
                    f"       └─ Open: {', '.join(str(p.port) for p in open_ports if p.state == 'open')}"
                )
        else:
            self._log(f"[DOWN] {ip}")

        result.scan_time = time.perf_counter() - t0
        return result

    # ─── Port scanning ────────────────────────────────────────────────────────

    def _scan_ports(self, ip: str, ports: List[int]) -> List[PortResult]:
        results: List[PortResult] = []

        with ThreadPoolExecutor(max_workers=min(self.max_workers, len(ports) or 1)) as ex:
            futures = {ex.submit(self._check_port, ip, p): p for p in ports}
            for fut in as_completed(futures):
                if self.stop_event.is_set():
                    break
                try:
                    pr = fut.result()
                    if pr:
                        results.append(pr)
                except Exception:
                    pass

        return sorted(results, key=lambda r: r.port)

    def _check_port(self, ip: str, port: int) -> Optional[PortResult]:
        """TCP connect to a single port. Returns PortResult only for open ports."""
        try:
            with socket.create_connection((ip, port), timeout=self.timeout) as _:
                pass  # Connection succeeded → port is open
        except ConnectionRefusedError:
            return None  # Port closed — skip
        except OSError:
            return None  # Filtered / other error — skip

        # Port is open — grab banner if requested
        banner  = None
        service = guess_service(port)

        if self.grab_banners:
            banner  = grab_banner(ip, port, timeout=max(self.timeout, 1.5))
            service = identify_service(port, banner)

        return PortResult(port=port, state="open", service=service, banner=banner)

    # ─── Host discovery ───────────────────────────────────────────────────────

    def _is_alive(self, ip: str) -> bool:
        """
        Check if a host is alive.

        Tries ICMP ping first (works without root on most systems via subprocess).
        Falls back to a quick TCP probe on port 80 / 443.
        """
        if self._ping(ip):
            return True
        # Fallback: try common ports quickly
        for port in (80, 443, 22, 135, 445):
            try:
                with socket.create_connection((ip, port), timeout=self.timeout):
                    return True
            except Exception:
                continue
        return False

    @staticmethod
    def _ping(ip: str) -> bool:
        """Send a single ICMP echo using the OS ping command."""
        system  = platform.system().lower()
        if system == "windows":
            cmd = ["ping", "-n", "1", "-w", "500", ip]
        else:
            cmd = ["ping", "-c", "1", "-W", "1", ip]
        try:
            result = subprocess.run(
                cmd,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                timeout=2,
            )
            return result.returncode == 0
        except Exception:
            return False

    # ─── Logging helper ───────────────────────────────────────────────────────

    def _log(self, msg: str) -> None:
        logger.info(msg)
        if self.log_cb:
            self.log_cb(msg)
