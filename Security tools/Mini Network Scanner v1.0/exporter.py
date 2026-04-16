"""
exporter.py — Export scan results to JSON and PDF.
"""

import json
from datetime import datetime
from pathlib import Path
from typing import List, Optional

from scanner import HostResult
from utils import setup_logger

logger = setup_logger("exporter")


# ─── JSON ─────────────────────────────────────────────────────────────────────

def export_json(
    results:    List[HostResult],
    target:     str,
    filepath:   str,
    ports_str:  str = "",
) -> str:
    """
    Serialize *results* to a JSON file.

    Returns the absolute path of the written file.
    """
    payload = {
        "meta": {
            "tool":       "Mini Network Scanner",
            "version":    "1.0.0",
            "target":     target,
            "ports":      ports_str,
            "timestamp":  datetime.utcnow().isoformat() + "Z",
            "total_hosts_scanned": len(results),
            "total_hosts_up":      sum(1 for r in results if r.status == "up"),
        },
        "hosts": [],
    }

    for hr in results:
        host_dict = {
            "ip":        hr.ip,
            "hostname":  hr.hostname,
            "status":    hr.status,
            "scan_time": round(hr.scan_time, 4),
            "open_ports": [
                {
                    "port":    pr.port,
                    "service": pr.service,
                    "banner":  pr.banner,
                }
                for pr in hr.open_ports
            ],
        }
        payload["hosts"].append(host_dict)

    path = Path(filepath)
    path.write_text(json.dumps(payload, indent=2, ensure_ascii=False), encoding="utf-8")
    logger.info("JSON exported → %s", path)
    return str(path.resolve())


# ─── PDF ──────────────────────────────────────────────────────────────────────

def export_pdf(
    results:   List[HostResult],
    target:    str,
    filepath:  str,
    ports_str: str = "",
) -> str:
    """
    Generate a professional PDF report of *results*.

    Returns the absolute path of the written file.
    Requires: reportlab
    """
    try:
        from reportlab.lib import colors
        from reportlab.lib.pagesizes import A4
        from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
        from reportlab.lib.units import cm
        from reportlab.platypus import (
            SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, HRFlowable,
        )
    except ImportError as exc:
        raise RuntimeError("reportlab is required for PDF export. Run: pip install reportlab") from exc

    path = Path(filepath)
    doc  = SimpleDocTemplate(
        str(path),
        pagesize=A4,
        leftMargin=2*cm, rightMargin=2*cm,
        topMargin=2*cm,  bottomMargin=2*cm,
    )

    # ── Style definitions ─────────────────────────────────────────────────────
    styles = getSampleStyleSheet()
    DARK    = colors.HexColor("#0d1117")
    ACCENT  = colors.HexColor("#00d4aa")
    ACCENT2 = colors.HexColor("#58a6ff")
    LIGHT   = colors.HexColor("#e6edf3")
    MUTED   = colors.HexColor("#8b949e")
    SUCCESS = colors.HexColor("#3fb950")
    DANGER  = colors.HexColor("#f85149")
    PANEL   = colors.HexColor("#161b22")
    BORDER  = colors.HexColor("#30363d")

    s_title = ParagraphStyle(
        "Title", parent=styles["Normal"],
        fontSize=22, textColor=ACCENT, spaceAfter=4, leading=28,
        fontName="Helvetica-Bold",
    )
    s_subtitle = ParagraphStyle(
        "Subtitle", parent=styles["Normal"],
        fontSize=11, textColor=MUTED, spaceAfter=12,
        fontName="Helvetica",
    )
    s_section = ParagraphStyle(
        "Section", parent=styles["Normal"],
        fontSize=13, textColor=ACCENT2, spaceBefore=14, spaceAfter=6,
        fontName="Helvetica-Bold",
    )
    s_body = ParagraphStyle(
        "Body", parent=styles["Normal"],
        fontSize=9, textColor=LIGHT, leading=14,
        fontName="Helvetica",
    )
    s_small = ParagraphStyle(
        "Small", parent=styles["Normal"],
        fontSize=8, textColor=MUTED,
        fontName="Helvetica",
    )
    s_banner = ParagraphStyle(
        "Banner", parent=styles["Normal"],
        fontSize=7.5, textColor=MUTED, leading=11,
        fontName="Courier",
    )

    # ── Document content ──────────────────────────────────────────────────────
    story = []
    now   = datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S UTC")
    hosts_up   = [r for r in results if r.status == "up"]
    hosts_down = [r for r in results if r.status != "up"]

    # Header
    story.append(Paragraph("🔍 Mini Network Scanner", s_title))
    story.append(Paragraph("Security Assessment Report", s_subtitle))
    story.append(HRFlowable(width="100%", thickness=1, color=BORDER))
    story.append(Spacer(1, 0.3*cm))

    # Summary table
    summary_data = [
        ["Parameter", "Value"],
        ["Target",           target],
        ["Port Range",        ports_str or "—"],
        ["Scan Date",         now],
        ["Hosts Scanned",     str(len(results))],
        ["Hosts Up",          str(len(hosts_up))],
        ["Hosts Down",        str(len(hosts_down))],
        ["Total Open Ports",  str(sum(len(r.open_ports) for r in hosts_up))],
    ]
    summary_tbl = Table(summary_data, colWidths=[5*cm, 12*cm])
    summary_tbl.setStyle(TableStyle([
        ("BACKGROUND",  (0, 0), (-1, 0), ACCENT),
        ("TEXTCOLOR",   (0, 0), (-1, 0), DARK),
        ("FONTNAME",    (0, 0), (-1, 0), "Helvetica-Bold"),
        ("FONTSIZE",    (0, 0), (-1, -1), 9),
        ("BACKGROUND",  (0, 1), (-1, -1), PANEL),
        ("TEXTCOLOR",   (0, 1), (-1, -1), LIGHT),
        ("ROWBACKGROUNDS", (0, 1), (-1, -1), [PANEL, colors.HexColor("#1c2128")]),
        ("GRID",        (0, 0), (-1, -1), 0.4, BORDER),
        ("LEFTPADDING", (0, 0), (-1, -1), 8),
        ("RIGHTPADDING",(0, 0), (-1, -1), 8),
        ("TOPPADDING",  (0, 0), (-1, -1), 5),
        ("BOTTOMPADDING",(0,0), (-1, -1), 5),
    ]))
    story.append(summary_tbl)
    story.append(Spacer(1, 0.5*cm))

    # ── Per-host details ──────────────────────────────────────────────────────
    story.append(Paragraph("Host Details", s_section))
    story.append(HRFlowable(width="100%", thickness=0.5, color=BORDER))
    story.append(Spacer(1, 0.2*cm))

    for hr in sorted(results, key=lambda r: _ip_key(r.ip)):
        status_color = SUCCESS if hr.status == "up" else DANGER
        status_label = "● UP" if hr.status == "up" else "● DOWN"

        # Host header row
        host_header = [
            [
                Paragraph(f"<b>{hr.ip}</b>", s_body),
                Paragraph(hr.hostname or "—", s_small),
                Paragraph(f"<font color='{'#3fb950' if hr.status=='up' else '#f85149'}'>{status_label}</font>", s_body),
                Paragraph(f"{hr.scan_time:.2f}s", s_small),
            ]
        ]
        host_hdr_tbl = Table(host_header, colWidths=[4*cm, 5.5*cm, 3*cm, 4.5*cm])
        host_hdr_tbl.setStyle(TableStyle([
            ("BACKGROUND",  (0, 0), (-1, -1), colors.HexColor("#1c2128")),
            ("TEXTCOLOR",   (0, 0), (-1, -1), LIGHT),
            ("FONTSIZE",    (0, 0), (-1, -1), 9),
            ("GRID",        (0, 0), (-1, -1), 0.3, BORDER),
            ("LEFTPADDING", (0, 0), (-1, -1), 6),
            ("TOPPADDING",  (0, 0), (-1, -1), 4),
            ("BOTTOMPADDING",(0,0), (-1, -1), 4),
        ]))
        story.append(host_hdr_tbl)

        # Port table (only if host is up and has open ports)
        if hr.status == "up" and hr.open_ports:
            port_data = [["Port", "Service", "Banner"]]
            for pr in hr.open_ports:
                banner_text = (pr.banner or "—")[:120]
                port_data.append([
                    str(pr.port),
                    pr.service,
                    Paragraph(banner_text, s_banner),
                ])
            port_tbl = Table(port_data, colWidths=[2*cm, 3*cm, 12*cm])
            port_tbl.setStyle(TableStyle([
                ("BACKGROUND",  (0, 0), (-1, 0), colors.HexColor("#21262d")),
                ("TEXTCOLOR",   (0, 0), (-1, 0), MUTED),
                ("FONTNAME",    (0, 0), (-1, 0), "Helvetica-Bold"),
                ("FONTSIZE",    (0, 0), (-1, -1), 8),
                ("BACKGROUND",  (0, 1), (-1, -1), PANEL),
                ("TEXTCOLOR",   (0, 1), (-1, -1), LIGHT),
                ("ROWBACKGROUNDS", (0, 1), (-1, -1), [PANEL, colors.HexColor("#1c2128")]),
                ("GRID",        (0, 0), (-1, -1), 0.3, BORDER),
                ("LEFTPADDING", (0, 0), (-1, -1), 6),
                ("TOPPADDING",  (0, 0), (-1, -1), 3),
                ("BOTTOMPADDING",(0,0), (-1, -1), 3),
                ("VALIGN",      (0, 0), (-1, -1), "TOP"),
            ]))
            story.append(port_tbl)
        elif hr.status == "up":
            story.append(Paragraph("  No open ports found in the scanned range.", s_small))

        story.append(Spacer(1, 0.25*cm))

    # Footer note
    story.append(HRFlowable(width="100%", thickness=0.5, color=BORDER))
    story.append(Spacer(1, 0.2*cm))
    story.append(Paragraph(
        "⚠  This report is generated for authorised security assessment purposes only. "
        "Unauthorised scanning may be illegal.",
        s_small,
    ))

    doc.build(story)
    logger.info("PDF exported → %s", path)
    return str(path.resolve())


def _ip_key(ip: str):
    """Sort key for IPs as tuples of integers."""
    try:
        return tuple(int(p) for p in ip.split("."))
    except Exception:
        return (0, 0, 0, 0)
