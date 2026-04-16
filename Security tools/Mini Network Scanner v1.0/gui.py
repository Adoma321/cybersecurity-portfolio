"""
gui.py — Modern dark-theme GUI for Mini Network Scanner using CustomTkinter.
"""

import queue
import threading
import time
import tkinter as tk
from datetime import datetime
from pathlib import Path
from threading import Event
from tkinter import filedialog, messagebox
from typing import List, Optional

import customtkinter as ctk

from scanner import HostResult, NetworkScanner
from exporter import export_json, export_pdf
from utils import parse_targets, parse_port_range, format_duration, COLORS

# ─── CustomTkinter theme ──────────────────────────────────────────────────────
ctk.set_appearance_mode("dark")
ctk.set_default_color_theme("dark-blue")


# ─── Constants ────────────────────────────────────────────────────────────────
APP_TITLE   = "Mini Network Scanner  v1.0"
WIN_W, WIN_H = 1200, 760
FONT_MONO   = ("Consolas", 11)
FONT_MONO_S = ("Consolas", 10)
FONT_UI     = ("Segoe UI", 11)
FONT_UI_B   = ("Segoe UI", 11, "bold")
FONT_SMALL  = ("Segoe UI", 9)
FONT_TITLE  = ("Segoe UI", 18, "bold")

BG      = COLORS["bg"]
PANEL   = COLORS["panel"]
BORDER  = COLORS["border"]
ACCENT  = COLORS["accent"]
ACCENT2 = COLORS["accent2"]
DANGER  = COLORS["danger"]
SUCCESS = COLORS["success"]
TEXT    = COLORS["text"]
MUTED   = COLORS["muted"]


# ═══════════════════════════════════════════════════════════════════════════════
class ScannerApp(ctk.CTk):
    """Main application window."""

    def __init__(self):
        super().__init__()
        self.title(APP_TITLE)
        self.geometry(f"{WIN_W}x{WIN_H}")
        self.minsize(900, 600)
        self.configure(fg_color=BG)

        # State
        self._results:    List[HostResult] = []
        self._stop_event: Event = Event()
        self._scan_thread: Optional[threading.Thread] = None
        self._log_queue:  queue.Queue = queue.Queue()
        self._result_queue: queue.Queue = queue.Queue()
        self._scan_start: float = 0.0
        self._total_hosts: int = 0
        self._done_hosts:  int = 0

        self._build_ui()
        self._poll_queues()

    # ─── UI construction ──────────────────────────────────────────────────────

    def _build_ui(self):
        self.grid_columnconfigure(0, weight=1)
        self.grid_rowconfigure(1, weight=1)

        self._build_header()
        self._build_main()
        self._build_statusbar()

    def _build_header(self):
        hdr = ctk.CTkFrame(self, fg_color=PANEL, height=60, corner_radius=0)
        hdr.grid(row=0, column=0, sticky="ew", pady=(0, 1))
        hdr.grid_columnconfigure(1, weight=1)

        # Logo / title
        icon_lbl = ctk.CTkLabel(hdr, text="⬡", font=("Segoe UI", 28), text_color=ACCENT)
        icon_lbl.grid(row=0, column=0, padx=(18, 6), pady=8)

        title_lbl = ctk.CTkLabel(hdr, text=APP_TITLE, font=FONT_TITLE, text_color=TEXT)
        title_lbl.grid(row=0, column=1, sticky="w")

        ts_lbl = ctk.CTkLabel(hdr, text="Cybersecurity Toolkit", font=FONT_SMALL, text_color=MUTED)
        ts_lbl.grid(row=0, column=2, padx=18, sticky="e")

    def _build_main(self):
        main = ctk.CTkFrame(self, fg_color=BG, corner_radius=0)
        main.grid(row=1, column=0, sticky="nsew")
        main.grid_columnconfigure(0, weight=0)
        main.grid_columnconfigure(1, weight=1)
        main.grid_rowconfigure(0, weight=1)

        self._build_sidebar(main)
        self._build_content(main)

    def _build_sidebar(self, parent):
        sb = ctk.CTkFrame(parent, fg_color=PANEL, width=300, corner_radius=0)
        sb.grid(row=0, column=0, sticky="ns", padx=(0, 1))
        sb.grid_propagate(False)
        sb.grid_columnconfigure(0, weight=1)

        # ── Scan Configuration ────────────────────────────────────────────────
        self._section_label(sb, "⚙  SCAN CONFIGURATION", row=0)

        # Target
        self._field_label(sb, "Target IP / Range / CIDR", row=1)
        self.target_entry = self._entry(sb, "192.168.1.0/24", row=2)

        # Ports
        self._field_label(sb, "Port Range", row=3)
        self.ports_entry = self._entry(sb, "1-1024", row=4)

        # Timeout
        self._field_label(sb, "Timeout (seconds)", row=5)
        self.timeout_entry = self._entry(sb, "1.0", row=6)

        # Max workers
        self._field_label(sb, "Max Threads", row=7)
        self.threads_entry = self._entry(sb, "100", row=8)

        # Banner grabbing
        self.banner_var = ctk.BooleanVar(value=True)
        banner_cb = ctk.CTkCheckBox(
            sb, text="  Banner Grabbing", variable=self.banner_var,
            font=FONT_UI, text_color=TEXT,
            fg_color=ACCENT, hover_color=ACCENT,
            checkmark_color=BG,
        )
        banner_cb.grid(row=9, column=0, sticky="w", padx=16, pady=(8, 0))

        # Divider
        ctk.CTkFrame(sb, fg_color=BORDER, height=1).grid(
            row=10, column=0, sticky="ew", padx=12, pady=14)

        # ── Scan Controls ────────────────────────────────────────────────────
        self._section_label(sb, "▶  CONTROLS", row=11)

        self.start_btn = self._btn(sb, "▶  Start Scan",  ACCENT,  self._on_start, row=12)
        self.stop_btn  = self._btn(sb, "■  Stop Scan",   DANGER,  self._on_stop,  row=13, state="disabled")

        ctk.CTkFrame(sb, fg_color=BORDER, height=1).grid(
            row=14, column=0, sticky="ew", padx=12, pady=14)

        # ── Export Controls ──────────────────────────────────────────────────
        self._section_label(sb, "💾  EXPORT", row=15)

        self.json_btn = self._btn(sb, "⬇  Export JSON", ACCENT2, self._on_export_json, row=16, state="disabled")
        self.pdf_btn  = self._btn(sb, "⬇  Export PDF",  ACCENT2, self._on_export_pdf,  row=17, state="disabled")

        ctk.CTkFrame(sb, fg_color=BORDER, height=1).grid(
            row=18, column=0, sticky="ew", padx=12, pady=14)

        # ── Progress ─────────────────────────────────────────────────────────
        self._section_label(sb, "📊  PROGRESS", row=19)

        self.progress_bar = ctk.CTkProgressBar(
            sb, mode="determinate", progress_color=ACCENT,
            fg_color=BORDER, height=10,
        )
        self.progress_bar.set(0)
        self.progress_bar.grid(row=20, column=0, sticky="ew", padx=16, pady=(4, 2))

        self.progress_label = ctk.CTkLabel(
            sb, text="0 / 0 hosts", font=FONT_SMALL, text_color=MUTED)
        self.progress_label.grid(row=21, column=0, padx=16, sticky="w")

        # ── Status ────────────────────────────────────────────────────────────
        self.status_lbl = ctk.CTkLabel(
            sb,
            text="● IDLE",
            font=("Segoe UI", 12, "bold"),
            text_color=MUTED,
        )
        self.status_lbl.grid(row=22, column=0, padx=16, pady=(12, 0), sticky="w")

    def _build_content(self, parent):
        content = ctk.CTkFrame(parent, fg_color=BG, corner_radius=0)
        content.grid(row=0, column=1, sticky="nsew")
        content.grid_columnconfigure(0, weight=1)
        content.grid_rowconfigure(0, weight=3)
        content.grid_rowconfigure(1, weight=0)
        content.grid_rowconfigure(2, weight=2)

        # ── Results table ─────────────────────────────────────────────────────
        result_frame = ctk.CTkFrame(content, fg_color=PANEL, corner_radius=8)
        result_frame.grid(row=0, column=0, sticky="nsew", padx=10, pady=(10, 4))
        result_frame.grid_columnconfigure(0, weight=1)
        result_frame.grid_rowconfigure(1, weight=1)

        ctk.CTkLabel(
            result_frame, text="SCAN RESULTS", font=FONT_UI_B,
            text_color=ACCENT, anchor="w",
        ).grid(row=0, column=0, sticky="ew", padx=12, pady=(8, 4))

        # Tkinter Text widget for results table (gives us full control)
        self.result_text = tk.Text(
            result_frame,
            bg=PANEL, fg=TEXT, font=FONT_MONO_S,
            insertbackground=ACCENT, relief="flat",
            selectbackground=ACCENT, selectforeground=BG,
            wrap="none", state="disabled",
            padx=8, pady=4,
        )
        self.result_text.grid(row=1, column=0, sticky="nsew")

        # Colour tags
        self.result_text.tag_configure("header", foreground=ACCENT, font=("Consolas", 10, "bold"))
        self.result_text.tag_configure("up",     foreground=SUCCESS)
        self.result_text.tag_configure("down",   foreground=DANGER)
        self.result_text.tag_configure("port",   foreground=ACCENT2)
        self.result_text.tag_configure("banner", foreground=MUTED)
        self.result_text.tag_configure("dim",    foreground=MUTED)

        r_scroll_y = ctk.CTkScrollbar(result_frame, command=self.result_text.yview)
        r_scroll_y.grid(row=1, column=1, sticky="ns")
        r_scroll_x = ctk.CTkScrollbar(result_frame, orientation="horizontal", command=self.result_text.xview)
        r_scroll_x.grid(row=2, column=0, sticky="ew")
        self.result_text.configure(yscrollcommand=r_scroll_y.set, xscrollcommand=r_scroll_x.set)

        # ── Divider ───────────────────────────────────────────────────────────
        ctk.CTkFrame(content, fg_color=BORDER, height=1).grid(
            row=1, column=0, sticky="ew", padx=10, pady=2)

        # ── Log panel ─────────────────────────────────────────────────────────
        log_frame = ctk.CTkFrame(content, fg_color=PANEL, corner_radius=8)
        log_frame.grid(row=2, column=0, sticky="nsew", padx=10, pady=(4, 10))
        log_frame.grid_columnconfigure(0, weight=1)
        log_frame.grid_rowconfigure(1, weight=1)

        log_hdr = ctk.CTkFrame(log_frame, fg_color="transparent")
        log_hdr.grid(row=0, column=0, columnspan=2, sticky="ew", padx=12, pady=(8, 4))
        log_hdr.grid_columnconfigure(0, weight=1)

        ctk.CTkLabel(log_hdr, text="REAL-TIME LOG", font=FONT_UI_B, text_color=ACCENT2, anchor="w").grid(
            row=0, column=0, sticky="w")
        ctk.CTkButton(log_hdr, text="Clear", font=FONT_SMALL, width=60, height=22,
                      fg_color=BORDER, hover_color=ACCENT2, text_color=TEXT,
                      command=self._clear_log).grid(row=0, column=1, sticky="e")

        self.log_text = tk.Text(
            log_frame,
            bg=BG, fg=MUTED, font=FONT_MONO_S,
            relief="flat", state="disabled",
            padx=8, pady=4, height=8,
            insertbackground=ACCENT,
        )
        self.log_text.grid(row=1, column=0, sticky="nsew")
        self.log_text.tag_configure("info",    foreground=MUTED)
        self.log_text.tag_configure("success", foreground=SUCCESS)
        self.log_text.tag_configure("error",   foreground=DANGER)
        self.log_text.tag_configure("warn",    foreground=COLORS["warning"])

        log_scroll = ctk.CTkScrollbar(log_frame, command=self.log_text.yview)
        log_scroll.grid(row=1, column=1, sticky="ns")
        self.log_text.configure(yscrollcommand=log_scroll.set)

    def _build_statusbar(self):
        bar = ctk.CTkFrame(self, fg_color=PANEL, height=28, corner_radius=0)
        bar.grid(row=2, column=0, sticky="ew")
        bar.grid_columnconfigure(1, weight=1)

        self.time_lbl = ctk.CTkLabel(bar, text="Ready", font=FONT_SMALL, text_color=MUTED)
        self.time_lbl.grid(row=0, column=0, padx=14, pady=4, sticky="w")

        self.stat_lbl = ctk.CTkLabel(bar, text="", font=FONT_SMALL, text_color=MUTED)
        self.stat_lbl.grid(row=0, column=2, padx=14, pady=4, sticky="e")

    # ─── Widget factories ─────────────────────────────────────────────────────

    def _section_label(self, parent, text, row):
        ctk.CTkLabel(parent, text=text, font=("Segoe UI", 9, "bold"),
                     text_color=MUTED, anchor="w").grid(
            row=row, column=0, sticky="ew", padx=16, pady=(12, 2))

    def _field_label(self, parent, text, row):
        ctk.CTkLabel(parent, text=text, font=FONT_SMALL, text_color=MUTED, anchor="w").grid(
            row=row, column=0, sticky="ew", padx=16, pady=(6, 0))

    def _entry(self, parent, placeholder, row):
        e = ctk.CTkEntry(
            parent, placeholder_text=placeholder,
            fg_color=BG, border_color=BORDER,
            text_color=TEXT, placeholder_text_color=MUTED,
            font=FONT_MONO_S, height=32, corner_radius=6,
        )
        e.grid(row=row, column=0, sticky="ew", padx=16, pady=(2, 0))
        return e

    def _btn(self, parent, text, color, command, row, state="normal"):
        b = ctk.CTkButton(
            parent, text=text, command=command,
            fg_color=color, hover_color=_darken(color),
            text_color=BG if color == ACCENT else TEXT,
            font=FONT_UI_B, height=36, corner_radius=6, state=state,
        )
        b.grid(row=row, column=0, sticky="ew", padx=16, pady=(6, 0))
        return b

    # ─── Scan controls ────────────────────────────────────────────────────────

    def _on_start(self):
        target_raw = self.target_entry.get().strip()
        ports_raw  = self.ports_entry.get().strip()
        timeout_s  = self.timeout_entry.get().strip()
        threads_s  = self.threads_entry.get().strip()

        if not target_raw or not ports_raw:
            messagebox.showerror("Input Error", "Target and port range are required.")
            return

        try:
            targets = parse_targets(target_raw)
            ports   = parse_port_range(ports_raw)
            timeout = float(timeout_s) if timeout_s else 1.0
            threads = int(threads_s)   if threads_s else 100
        except Exception as exc:
            messagebox.showerror("Input Error", str(exc))
            return

        # Reset state
        self._results.clear()
        self._stop_event.clear()
        self._total_hosts = len(targets)
        self._done_hosts  = 0
        self._scan_start  = time.perf_counter()

        self._clear_results()
        self._update_status("SCANNING", ACCENT)
        self._set_controls(scanning=True)

        self._write_result(
            f"{'─'*90}\n"
            f"  TARGET   : {target_raw}\n"
            f"  PORTS    : {ports_raw}\n"
            f"  HOSTS    : {self._total_hosts}\n"
            f"  THREADS  : {threads}\n"
            f"  TIMEOUT  : {timeout}s\n"
            f"{'─'*90}\n\n",
            tag="header",
        )
        self._write_result(
            f"{'IP ADDRESS':<18} {'STATUS':<8} {'OPEN PORTS':<30} {'HOSTNAME'}\n",
            tag="header",
        )
        self._write_result("─" * 90 + "\n", tag="dim")

        self._log("Starting scan …", "info")

        scanner = NetworkScanner(
            timeout=timeout,
            max_workers=threads,
            grab_banners=self.banner_var.get(),
            stop_event=self._stop_event,
            progress_cb=self._on_progress,
            result_cb=self._on_result,
            log_cb=lambda m: self._log_queue.put(("info", m)),
        )

        self._scan_thread = threading.Thread(
            target=self._run_scan,
            args=(scanner, targets, ports, ports_raw),
            daemon=True,
        )
        self._scan_thread.start()

    def _run_scan(self, scanner, targets, ports, ports_raw):
        results = scanner.scan(targets, ports)
        self._results = results
        self._result_queue.put(("done", results, ports_raw))

    def _on_stop(self):
        self._stop_event.set()
        self._log("Stop requested — finishing current threads …", "warn")
        self._update_status("STOPPING …", COLORS["warning"])

    def _on_progress(self, done, total):
        self._done_hosts = done
        # Update via queue (thread-safe)
        self._log_queue.put(("__progress__", done, total))

    def _on_result(self, result: HostResult):
        self._result_queue.put(("host", result))

    # ─── Export ───────────────────────────────────────────────────────────────

    def _on_export_json(self):
        if not self._results:
            messagebox.showinfo("No Results", "Run a scan first.")
            return
        path = filedialog.asksaveasfilename(
            defaultextension=".json",
            filetypes=[("JSON", "*.json"), ("All", "*.*")],
            initialfile=f"scan_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json",
        )
        if not path:
            return
        try:
            target = self.target_entry.get().strip()
            ports  = self.ports_entry.get().strip()
            out    = export_json(self._results, target, path, ports)
            self._log(f"JSON saved → {out}", "success")
            messagebox.showinfo("Exported", f"JSON saved:\n{out}")
        except Exception as exc:
            messagebox.showerror("Export Error", str(exc))

    def _on_export_pdf(self):
        if not self._results:
            messagebox.showinfo("No Results", "Run a scan first.")
            return
        path = filedialog.asksaveasfilename(
            defaultextension=".pdf",
            filetypes=[("PDF", "*.pdf"), ("All", "*.*")],
            initialfile=f"scan_{datetime.now().strftime('%Y%m%d_%H%M%S')}.pdf",
        )
        if not path:
            return
        try:
            target = self.target_entry.get().strip()
            ports  = self.ports_entry.get().strip()
            out    = export_pdf(self._results, target, path, ports)
            self._log(f"PDF saved → {out}", "success")
            messagebox.showinfo("Exported", f"PDF saved:\n{out}")
        except Exception as exc:
            messagebox.showerror("Export Error", str(exc))

    # ─── Queue polling (runs on main thread) ──────────────────────────────────

    def _poll_queues(self):
        # Log queue
        while not self._log_queue.empty():
            item = self._log_queue.get_nowait()
            if item[0] == "__progress__":
                _, done, total = item
                frac = done / total if total else 0
                self.progress_bar.set(frac)
                self.progress_label.configure(text=f"{done} / {total} hosts")
                elapsed = time.perf_counter() - self._scan_start
                self.time_lbl.configure(text=f"Elapsed: {format_duration(elapsed)}")
            else:
                level, msg = item[0], item[1]
                self._log(msg, level)

        # Result queue
        while not self._result_queue.empty():
            item = self._result_queue.get_nowait()
            if item[0] == "host":
                self._render_host_row(item[1])
            elif item[0] == "done":
                self._on_scan_done(item[1], item[2])

        self.after(80, self._poll_queues)

    # ─── Rendering helpers ────────────────────────────────────────────────────

    def _render_host_row(self, hr: HostResult):
        status_tag = "up" if hr.status == "up" else "down"
        status_str = "UP  " if hr.status == "up" else "DOWN"
        open_ps    = ", ".join(str(p.port) for p in hr.open_ports) or "—"
        hostname   = hr.hostname or ""

        line = f"{hr.ip:<18} "
        self._write_result(line)
        self._write_result(f"{status_str:<8} ", tag=status_tag)

        if hr.status == "up" and hr.open_ports:
            self._write_result(f"{open_ps:<30} ", tag="port")
        else:
            self._write_result(f"{'—':<30} ", tag="dim")

        self._write_result(f"{hostname}\n", tag="dim")

        # Show banners on indented lines
        for pr in hr.open_ports:
            if pr.banner:
                banner_short = pr.banner[:80]
                self._write_result(
                    f"  {'':18} ├ {pr.port}/{pr.service}: {banner_short}\n",
                    tag="banner",
                )

    def _on_scan_done(self, results: List[HostResult], ports_raw: str):
        elapsed  = time.perf_counter() - self._scan_start
        up_count = sum(1 for r in results if r.status == "up")
        total_open = sum(len(r.open_ports) for r in results)

        self._write_result("\n" + "─" * 90 + "\n", tag="dim")
        self._write_result(
            f"  SCAN COMPLETE   │  Duration: {format_duration(elapsed)}  │"
            f"  Hosts up: {up_count}/{len(results)}  │  Open ports: {total_open}\n",
            tag="header",
        )
        self._write_result("─" * 90 + "\n", tag="dim")

        self._log(
            f"Done in {format_duration(elapsed)} — {up_count}/{len(results)} hosts up, "
            f"{total_open} open ports.",
            "success",
        )

        self.progress_bar.set(1.0)
        self.progress_label.configure(text=f"{len(results)} / {len(results)} hosts")
        self.time_lbl.configure(text=f"Done in {format_duration(elapsed)}")
        self.stat_lbl.configure(
            text=f"Hosts up: {up_count}  │  Open ports: {total_open}"
        )
        self._update_status("COMPLETED", SUCCESS)
        self._set_controls(scanning=False)

    # ─── Text widget helpers ──────────────────────────────────────────────────

    def _write_result(self, text: str, tag: str = ""):
        self.result_text.configure(state="normal")
        if tag:
            self.result_text.insert("end", text, tag)
        else:
            self.result_text.insert("end", text)
        self.result_text.see("end")
        self.result_text.configure(state="disabled")

    def _clear_results(self):
        self.result_text.configure(state="normal")
        self.result_text.delete("1.0", "end")
        self.result_text.configure(state="disabled")

    def _log(self, msg: str, level: str = "info"):
        ts  = datetime.now().strftime("%H:%M:%S")
        tag = level if level in ("success", "error", "warn") else "info"
        self.log_text.configure(state="normal")
        self.log_text.insert("end", f"[{ts}] {msg}\n", tag)
        self.log_text.see("end")
        self.log_text.configure(state="disabled")

    def _clear_log(self):
        self.log_text.configure(state="normal")
        self.log_text.delete("1.0", "end")
        self.log_text.configure(state="disabled")

    # ─── Control state helpers ────────────────────────────────────────────────

    def _update_status(self, text: str, color: str):
        self.status_lbl.configure(text=f"● {text}", text_color=color)

    def _set_controls(self, scanning: bool):
        self.start_btn.configure(state="disabled" if scanning else "normal")
        self.stop_btn.configure( state="normal"   if scanning else "disabled")
        self.json_btn.configure( state="disabled" if scanning else "normal")
        self.pdf_btn.configure(  state="disabled" if scanning else "normal")
        for entry in (self.target_entry, self.ports_entry, self.timeout_entry, self.threads_entry):
            entry.configure(state="disabled" if scanning else "normal")


# ─── Helper ───────────────────────────────────────────────────────────────────

def _darken(hex_color: str, factor: float = 0.75) -> str:
    """Return a darkened version of a hex colour."""
    h = hex_color.lstrip("#")
    r, g, b = int(h[0:2], 16), int(h[2:4], 16), int(h[4:6], 16)
    r, g, b = int(r * factor), int(g * factor), int(b * factor)
    return f"#{r:02x}{g:02x}{b:02x}"
