"""app/services/pdf_report_service.py — Professional PDF pentest report via reportlab."""
import io
from datetime import datetime, timezone

from reportlab.lib import colors
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import ParagraphStyle
from reportlab.lib.units import mm
from reportlab.platypus import (
    SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle,
    PageBreak, KeepTogether,
)
from reportlab.lib.enums import TA_LEFT, TA_CENTER, TA_JUSTIFY

PAGE_W, PAGE_H = A4

# ── Colour palette ─────────────────────────────────────────────────────────────
NAVY     = colors.HexColor("#0f172a")
NAVY_MID = colors.HexColor("#1e293b")
NAVY_L   = colors.HexColor("#334155")
SLATE    = colors.HexColor("#64748b")
CYAN     = colors.HexColor("#22d3ee")
WHITE    = colors.white
GREY_L   = colors.HexColor("#f1f5f9")
GREY_M   = colors.HexColor("#e2e8f0")

SEV_C = {
    "CRITICAL": colors.HexColor("#ef4444"),
    "HIGH":     colors.HexColor("#f97316"),
    "MEDIUM":   colors.HexColor("#eab308"),
    "LOW":      colors.HexColor("#22c55e"),
    "INFO":     colors.HexColor("#94a3b8"),
}
SEV_BG = {
    "CRITICAL": colors.HexColor("#fef2f2"),
    "HIGH":     colors.HexColor("#fff7ed"),
    "MEDIUM":   colors.HexColor("#fefce8"),
    "LOW":      colors.HexColor("#f0fdf4"),
    "INFO":     colors.HexColor("#f8fafc"),
}
SEV_ORDER = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]


def _sc(sev: str) -> colors.Color:
    return SEV_C.get((sev or "INFO").upper(), SLATE)


def _sbg(sev: str) -> colors.Color:
    return SEV_BG.get((sev or "INFO").upper(), GREY_L)


# ── Styles ─────────────────────────────────────────────────────────────────────
def _make_styles() -> dict:
    s: dict = {}

    def P(name: str, **kw):
        s[name] = ParagraphStyle(name, **kw)

    P("body",      fontName="Helvetica",       fontSize=10, textColor=NAVY_MID, leading=16, alignment=TA_JUSTIFY, spaceAfter=5)
    P("body_l",    fontName="Helvetica",       fontSize=10, textColor=NAVY_MID, leading=16, alignment=TA_LEFT,    spaceAfter=5)
    P("small",     fontName="Helvetica",       fontSize=8,  textColor=SLATE,    leading=12, spaceAfter=3)
    P("bold",      fontName="Helvetica-Bold",  fontSize=10, textColor=NAVY,     leading=15, spaceAfter=4)
    P("sec_num",   fontName="Helvetica-Bold",  fontSize=8,  textColor=CYAN,     leading=12, spaceAfter=1)
    P("sec_title", fontName="Helvetica-Bold",  fontSize=16, textColor=NAVY,     leading=22, spaceAfter=3)
    P("sub_title", fontName="Helvetica-Bold",  fontSize=12, textColor=NAVY,     leading=16, spaceAfter=4)
    P("find_h",    fontName="Helvetica-Bold",  fontSize=11, textColor=NAVY,     leading=15, spaceAfter=3)
    P("find_b",    fontName="Helvetica",       fontSize=9,  textColor=NAVY_L,   leading=14, spaceAfter=4)
    P("find_lbl",  fontName="Helvetica-Bold",  fontSize=7,  textColor=SLATE,    leading=10, spaceAfter=1)
    P("mono",      fontName="Courier",         fontSize=8,  textColor=colors.HexColor("#065f46"), leading=13, backColor=colors.HexColor("#f0fdf4"), borderPad=3)
    P("th",        fontName="Helvetica-Bold",  fontSize=8,  textColor=WHITE,    leading=12)
    P("td",        fontName="Helvetica",       fontSize=8,  textColor=NAVY_MID, leading=13)
    P("td_b",      fontName="Helvetica-Bold",  fontSize=8,  textColor=NAVY,     leading=13)
    P("td_m",      fontName="Courier",         fontSize=7,  textColor=colors.HexColor("#065f46"), leading=12)
    P("step",      fontName="Helvetica",       fontSize=10, textColor=NAVY_L,   leading=15, leftIndent=14, spaceAfter=4)
    return s


# ── Canvas helpers ─────────────────────────────────────────────────────────────
def _draw_cover(canvas, doc, scan_info: dict, ai_report: dict):
    canvas.saveState()
    w, h = PAGE_W, PAGE_H

    # Full dark background
    canvas.setFillColor(NAVY)
    canvas.rect(0, 0, w, h, fill=1, stroke=0)

    # Top accent bar
    canvas.setFillColor(CYAN)
    canvas.rect(0, h - 8, w, 8, fill=1, stroke=0)

    # Classification banner
    canvas.setFillColor(NAVY_MID)
    canvas.rect(0, h - 28, w, 20, fill=1, stroke=0)
    canvas.setFillColor(CYAN)
    canvas.setFont("Helvetica-Bold", 7.5)
    canvas.drawCentredString(w / 2, h - 20, "CONFIDENTIAL  //  PENTEST REPORT  //  AUTHORIZED PERSONNEL ONLY")

    # Brand
    canvas.setFillColor(CYAN)
    canvas.setFont("Helvetica-Bold", 11)
    canvas.drawString(20 * mm, h - 48, "MCPP")
    canvas.setFillColor(colors.HexColor("#475569"))
    canvas.setFont("Helvetica", 9)
    canvas.drawString(20 * mm + 38, h - 48, "Multi-Cloud Pentest Platform")

    # Main title block (center of page, slightly above center)
    cy = h * 0.56
    canvas.setFillColor(WHITE)
    canvas.setFont("Helvetica-Bold", 34)
    canvas.drawCentredString(w / 2, cy + 30, "CLOUD SECURITY")
    canvas.setFont("Helvetica-Bold", 34)
    canvas.drawCentredString(w / 2, cy - 6, "ASSESSMENT REPORT")

    # Cyan divider
    canvas.setStrokeColor(CYAN)
    canvas.setLineWidth(2)
    canvas.line(30 * mm, cy - 22, w - 30 * mm, cy - 22)

    # Meta info
    provider = scan_info.get("provider", "aws").upper()
    scan_id  = scan_info.get("scan_id", "—")
    name     = scan_info.get("name", "")
    date_str = datetime.now(timezone.utc).strftime("%B %d, %Y")

    canvas.setFillColor(colors.HexColor("#94a3b8"))
    canvas.setFont("Helvetica-Bold", 11)
    canvas.drawCentredString(w / 2, cy - 40, f"Cloud Provider: {provider}")
    if name:
        canvas.setFont("Helvetica", 10)
        canvas.drawCentredString(w / 2, cy - 56, name)
    canvas.setFont("Courier", 9)
    canvas.drawCentredString(w / 2, cy - 72, f"Scan: {scan_id}")
    canvas.setFont("Helvetica", 10)
    canvas.drawCentredString(w / 2, cy - 88, f"Generated: {date_str}")

    # Risk score box
    risk_score = ai_report.get("risk_score", 0)
    if risk_score >= 70:
        score_col   = SEV_C["CRITICAL"]
        risk_label  = "HIGH RISK"
    elif risk_score >= 40:
        score_col   = SEV_C["MEDIUM"]
        risk_label  = "MEDIUM RISK"
    else:
        score_col   = SEV_C["LOW"]
        risk_label  = "LOW RISK"

    bx = w / 2 - 32 * mm
    by = cy - 165
    bw = 64 * mm
    bh = 52 * mm

    canvas.setFillColor(NAVY_MID)
    canvas.roundRect(bx, by, bw, bh, 6, fill=1, stroke=0)
    canvas.setStrokeColor(score_col)
    canvas.setLineWidth(2)
    canvas.roundRect(bx, by, bw, bh, 6, fill=0, stroke=1)

    canvas.setFillColor(colors.HexColor("#94a3b8"))
    canvas.setFont("Helvetica-Bold", 7.5)
    canvas.drawCentredString(w / 2, by + bh - 12, "RISK SCORE")

    canvas.setFillColor(score_col)
    canvas.setFont("Helvetica-Bold", 40)
    canvas.drawCentredString(w / 2, by + bh / 2 - 10, str(risk_score))

    canvas.setFillColor(colors.HexColor("#64748b"))
    canvas.setFont("Helvetica", 9)
    canvas.drawCentredString(w / 2, by + 10, f"/ 100  ·  {risk_label}")

    # Bottom bar
    canvas.setFillColor(NAVY_MID)
    canvas.rect(0, 0, w, 16 * mm, fill=1, stroke=0)
    canvas.setFillColor(CYAN)
    canvas.rect(0, 16 * mm, w, 1.5, fill=1, stroke=0)
    canvas.setFillColor(colors.HexColor("#475569"))
    canvas.setFont("Helvetica", 7.5)
    canvas.drawString(20 * mm, 7 * mm, "CONFIDENTIAL")
    canvas.drawCentredString(w / 2, 7 * mm, "This document contains sensitive security information")
    canvas.drawRightString(w - 20 * mm, 7 * mm, "Page 1")

    canvas.restoreState()


def _draw_header_footer(canvas, doc, scan_info: dict):
    canvas.saveState()
    w, h = PAGE_W, PAGE_H

    # Header bar
    canvas.setFillColor(NAVY)
    canvas.rect(0, h - 14 * mm, w, 14 * mm, fill=1, stroke=0)
    canvas.setFillColor(CYAN)
    canvas.rect(0, h - 14 * mm - 1.5, w, 1.5, fill=1, stroke=0)
    canvas.setFillColor(WHITE)
    canvas.setFont("Helvetica-Bold", 8.5)
    canvas.drawString(20 * mm, h - 8.5 * mm, "CLOUD SECURITY ASSESSMENT REPORT")
    canvas.setFillColor(CYAN)
    canvas.setFont("Helvetica-Bold", 8)
    canvas.drawRightString(w - 20 * mm, h - 8.5 * mm, scan_info.get("provider", "").upper())

    # Footer bar
    canvas.setFillColor(GREY_L)
    canvas.rect(0, 0, w, 13 * mm, fill=1, stroke=0)
    canvas.setFillColor(NAVY)
    canvas.rect(0, 13 * mm, w, 1, fill=1, stroke=0)
    canvas.setFillColor(SLATE)
    canvas.setFont("Helvetica", 7.5)
    canvas.drawString(20 * mm, 5 * mm, "CONFIDENTIAL — AUTHORIZED USE ONLY")
    canvas.drawCentredString(w / 2, 5 * mm, scan_info.get("scan_id", "")[:24])
    canvas.drawRightString(w - 20 * mm, 5 * mm, f"Page {doc.page}")

    canvas.restoreState()


# ── Flow helpers ───────────────────────────────────────────────────────────────
def _section_header(st: list, styles: dict, num: str, title: str):
    st.append(Spacer(1, 4 * mm))
    st.append(Paragraph(f"// {num}", styles["sec_num"]))
    st.append(Paragraph(title, styles["sec_title"]))
    # Cyan rule via thin single-row table
    rule = Table([[""]], colWidths=[PAGE_W - 40 * mm])
    rule.setStyle(TableStyle([
        ("LINEBELOW", (0, 0), (-1, -1), 1.5, CYAN),
        ("TOPPADDING",    (0, 0), (-1, -1), 0),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 0),
    ]))
    st.append(rule)
    st.append(Spacer(1, 3 * mm))


def _sev_cell(sev: str, styles: dict):
    """Returns a Paragraph that looks like a colored severity badge in a table cell."""
    col = _sc(sev)
    return Paragraph(
        f'<font color="{col.hexval()}" name="Helvetica-Bold"><b>{sev.upper()}</b></font>',
        styles["td"],
    )


def _divider(styles: dict):
    d = Table([[""]], colWidths=[PAGE_W - 40 * mm])
    d.setStyle(TableStyle([
        ("LINEBELOW", (0, 0), (-1, -1), 0.5, GREY_M),
        ("TOPPADDING",    (0, 0), (-1, -1), 0),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 0),
    ]))
    return d


# ── Section builders ──────────────────────────────────────────────────────────
def _exec_summary(styles: dict, ai_report: dict, counts: dict) -> list:
    st: list = []
    _section_header(st, styles, "01", "EXECUTIVE SUMMARY")

    risk_score = ai_report.get("risk_score", 0)
    if risk_score >= 70:
        risk_label = "HIGH RISK"
        risk_col   = SEV_C["CRITICAL"]
    elif risk_score >= 40:
        risk_label = "MEDIUM RISK"
        risk_col   = SEV_C["MEDIUM"]
    else:
        risk_label = "LOW RISK"
        risk_col   = SEV_C["LOW"]

    # Risk score + summary side by side
    score_tbl = Table(
        [[
            Paragraph(str(risk_score), ParagraphStyle(
                "score_big", fontName="Helvetica-Bold", fontSize=40,
                textColor=risk_col, leading=48, alignment=TA_CENTER,
            )),
            Paragraph(
                ai_report.get("executive_summary", "No executive summary available."),
                styles["body"],
            ),
        ]],
        colWidths=[40 * mm, PAGE_W - 40 * mm - 40 * mm],
    )
    score_tbl.setStyle(TableStyle([
        ("VALIGN",        (0, 0), (-1, -1), "MIDDLE"),
        ("LEFTPADDING",   (0, 0), (0, 0),  0),
        ("RIGHTPADDING",  (0, 0), (0, 0),  8),
        ("LEFTPADDING",   (1, 0), (1, 0),  8),
        ("LINEAFTER",     (0, 0), (0, 0),  0.5, GREY_M),
        ("TOPPADDING",    (0, 0), (-1, -1), 6),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 6),
    ]))
    st.append(score_tbl)
    st.append(Paragraph(
        f'<font color="{risk_col.hexval()}"><b>{risk_label}</b></font>  ·  Risk Score: {risk_score} / 100',
        ParagraphStyle("risk_lbl", fontName="Helvetica-Bold", fontSize=9, textColor=SLATE, leading=14, alignment=TA_CENTER, spaceAfter=8),
    ))
    st.append(Spacer(1, 5 * mm))

    # Severity summary boxes
    sev_data = [
        [Paragraph("SEVERITY", styles["find_lbl"]),
         Paragraph("CRITICAL", styles["find_lbl"]),
         Paragraph("HIGH",     styles["find_lbl"]),
         Paragraph("MEDIUM",   styles["find_lbl"]),
         Paragraph("LOW",      styles["find_lbl"])],
        [Paragraph("FINDINGS", styles["find_lbl"]),
         Paragraph(str(counts.get("CRITICAL", 0)), ParagraphStyle("cv", fontName="Helvetica-Bold", fontSize=20, textColor=SEV_C["CRITICAL"], leading=24, alignment=TA_CENTER)),
         Paragraph(str(counts.get("HIGH",     0)), ParagraphStyle("hv", fontName="Helvetica-Bold", fontSize=20, textColor=SEV_C["HIGH"],     leading=24, alignment=TA_CENTER)),
         Paragraph(str(counts.get("MEDIUM",   0)), ParagraphStyle("mv", fontName="Helvetica-Bold", fontSize=20, textColor=SEV_C["MEDIUM"],   leading=24, alignment=TA_CENTER)),
         Paragraph(str(counts.get("LOW",      0)), ParagraphStyle("lv", fontName="Helvetica-Bold", fontSize=20, textColor=SEV_C["LOW"],      leading=24, alignment=TA_CENTER))],
    ]
    col_w = (PAGE_W - 40 * mm) / 5
    sev_tbl = Table(sev_data, colWidths=[col_w] * 5)
    sev_tbl.setStyle(TableStyle([
        ("BACKGROUND",    (0, 0), (0, -1), NAVY),
        ("BACKGROUND",    (1, 0), (1, -1), SEV_BG["CRITICAL"]),
        ("BACKGROUND",    (2, 0), (2, -1), SEV_BG["HIGH"]),
        ("BACKGROUND",    (3, 0), (3, -1), SEV_BG["MEDIUM"]),
        ("BACKGROUND",    (4, 0), (4, -1), SEV_BG["LOW"]),
        ("TEXTCOLOR",     (0, 0), (0, -1), WHITE),
        ("ALIGN",         (0, 0), (-1, -1), "CENTER"),
        ("VALIGN",        (0, 0), (-1, -1), "MIDDLE"),
        ("TOPPADDING",    (0, 0), (-1, -1), 8),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 8),
        ("GRID",          (0, 0), (-1, -1), 0.5, GREY_M),
        ("ROUNDEDCORNERS", [4]),
    ]))
    st.append(sev_tbl)
    return st


def _risk_overview(styles: dict, findings: list) -> list:
    st: list = []
    _section_header(st, styles, "02", "RISK OVERVIEW")

    total = len(findings)
    counts = {s: sum(1 for f in findings if (f.get("severity") or "INFO").upper() == s) for s in SEV_ORDER}

    st.append(Paragraph(
        f"This assessment identified <b>{total} security findings</b> across the cloud environment. "
        "The table below provides a complete severity breakdown and an estimate of remediation impact.",
        styles["body"],
    ))
    st.append(Spacer(1, 4 * mm))

    # Bar chart via table
    rows = []
    for sev in SEV_ORDER:
        cnt = counts.get(sev, 0)
        pct = (cnt / total * 100) if total else 0
        bar_filled  = max(1, int(pct)) if cnt else 0
        bar_empty   = 100 - bar_filled

        bar_tbl = Table(
            [["", ""] if bar_filled else [""]],
            colWidths=[bar_filled * 1.4, bar_empty * 1.4] if bar_filled else [140],
        )
        bar_tbl.setStyle(TableStyle([
            ("BACKGROUND",    (0, 0), (0, -1), _sc(sev)),
            ("BACKGROUND",    (1, 0), (1, -1), GREY_M) if bar_filled else ("BACKGROUND", (0, 0), (0, -1), GREY_M),
            ("TOPPADDING",    (0, 0), (-1, -1), 3),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 3),
            ("LEFTPADDING",   (0, 0), (-1, -1), 0),
            ("RIGHTPADDING",  (0, 0), (-1, -1), 0),
        ]))

        rows.append([
            Paragraph(sev, styles["td_b"]),
            Paragraph(str(cnt), ParagraphStyle("cnt", fontName="Helvetica-Bold", fontSize=10, textColor=_sc(sev), leading=13, alignment=TA_CENTER)),
            Paragraph(f"{pct:.0f}%", styles["td"]),
            bar_tbl,
        ])

    tbl = Table(rows, colWidths=[35 * mm, 18 * mm, 14 * mm, 100 * mm])
    tbl.setStyle(TableStyle([
        ("VALIGN",        (0, 0), (-1, -1), "MIDDLE"),
        ("LINEBELOW",     (0, 0), (-1, -2), 0.5, GREY_M),
        ("TOPPADDING",    (0, 0), (-1, -1), 6),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 6),
    ]))
    st.append(tbl)

    # Module breakdown
    modules: dict = {}
    for f in findings:
        m = f.get("module_id", "unknown")
        modules[m] = modules.get(m, 0) + 1

    if modules:
        st.append(Spacer(1, 6 * mm))
        st.append(Paragraph("Findings by Module", styles["sub_title"]))
        mrows = [[Paragraph("Module", styles["th"]), Paragraph("Findings", styles["th"])]]
        for mod, cnt in sorted(modules.items(), key=lambda x: -x[1]):
            mrows.append([Paragraph(mod, styles["td_b"]), Paragraph(str(cnt), styles["td"])])
        mtbl = Table(mrows, colWidths=[120 * mm, 40 * mm])
        mtbl.setStyle(TableStyle([
            ("BACKGROUND",    (0, 0), (-1, 0), NAVY),
            ("ROWBACKGROUNDS", (0, 1), (-1, -1), [WHITE, GREY_L]),
            ("TOPPADDING",    (0, 0), (-1, -1), 5),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 5),
            ("LEFTPADDING",   (0, 0), (-1, -1), 8),
            ("GRID",          (0, 0), (-1, -1), 0.5, GREY_M),
        ]))
        st.append(mtbl)

    return st


def _detailed_findings(styles: dict, findings: list, ai_report: dict) -> list:
    st: list = []
    _section_header(st, styles, "03", "DETAILED FINDINGS")

    # Build AI enrichment map (title → AI finding)
    ai_map = {(f.get("title") or "").lower(): f for f in (ai_report.get("findings") or [])}

    # Group by severity
    groups: dict = {s: [] for s in SEV_ORDER}
    for f in findings:
        sev = (f.get("severity") or "INFO").upper()
        groups.setdefault(sev, []).append(f)

    st.append(Paragraph(
        f"All {len(findings)} findings are listed below, grouped by severity (critical first). "
        "AI-enhanced remediation guidance is provided where available.",
        styles["body"],
    ))
    st.append(Spacer(1, 4 * mm))

    for sev in SEV_ORDER:
        grp = groups.get(sev, [])
        if not grp:
            continue

        sev_col = _sc(sev)
        sev_bg  = _sbg(sev)

        # Severity group header bar
        hdr_tbl = Table(
            [[Paragraph(f"  {sev}  ({len(grp)} finding{'s' if len(grp) != 1 else ''})", ParagraphStyle(
                f"shdr_{sev}", fontName="Helvetica-Bold", fontSize=11, textColor=WHITE, leading=16,
            ))]],
            colWidths=[PAGE_W - 40 * mm],
        )
        hdr_tbl.setStyle(TableStyle([
            ("BACKGROUND",    (0, 0), (-1, -1), sev_col),
            ("TOPPADDING",    (0, 0), (-1, -1), 7),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 7),
            ("LEFTPADDING",   (0, 0), (-1, -1), 10),
        ]))
        st.append(KeepTogether([hdr_tbl, Spacer(1, 3 * mm)]))

        for i, f in enumerate(grp, 1):
            ai_f     = ai_map.get((f.get("title") or "").lower(), {})
            title    = f.get("title", "Untitled Finding")
            resource = f.get("affected_resource", "")
            desc     = ai_f.get("explanation") or f.get("description", "")
            remed    = ai_f.get("remediation_guidance") or f.get("remediation", "")
            fix_cli  = ai_f.get("fix_cli", "")
            cis      = f.get("cis_controls") or []
            region   = f.get("region", "")
            module   = f.get("module_id", "")

            block: list = []

            # Title row
            block.append(Paragraph(f"{i}. {title}", styles["find_h"]))

            # Meta row: resource / module / region
            meta_parts = []
            if resource:
                meta_parts.append(f"<b>Resource:</b> {resource}")
            if module:
                meta_parts.append(f"<b>Module:</b> {module}")
            if region:
                meta_parts.append(f"<b>Region:</b> {region}")
            if meta_parts:
                block.append(Paragraph("  ·  ".join(meta_parts), styles["small"]))

            # Description
            if desc:
                block.append(Paragraph("<b>Description</b>", styles["find_lbl"]))
                block.append(Paragraph(desc, styles["find_b"]))

            # Remediation guidance
            if remed:
                rem_tbl = Table(
                    [[Paragraph(remed, styles["find_b"])]],
                    colWidths=[PAGE_W - 40 * mm - 4 * mm],
                )
                rem_tbl.setStyle(TableStyle([
                    ("BACKGROUND",    (0, 0), (-1, -1), colors.HexColor("#f0fdf4")),
                    ("LEFTPADDING",   (0, 0), (-1, -1), 8),
                    ("RIGHTPADDING",  (0, 0), (-1, -1), 8),
                    ("TOPPADDING",    (0, 0), (-1, -1), 6),
                    ("BOTTOMPADDING", (0, 0), (-1, -1), 6),
                    ("LINEBEFORE",    (0, 0), (0, -1),  3, SEV_C["LOW"]),
                ]))
                block.append(Paragraph("<b>Remediation Guidance</b>", styles["find_lbl"]))
                block.append(rem_tbl)
                block.append(Spacer(1, 2 * mm))

            # CLI fix
            if fix_cli:
                block.append(Paragraph("<b>Fix Command</b>", styles["find_lbl"]))
                block.append(Paragraph(fix_cli, styles["mono"]))
                block.append(Spacer(1, 2 * mm))

            # CIS controls
            if cis:
                block.append(Paragraph(f"<b>CIS Controls:</b>  {',  '.join(cis)}", styles["small"]))

            block.append(Spacer(1, 2 * mm))
            block.append(_divider(styles))
            block.append(Spacer(1, 3 * mm))

            st.append(KeepTogether(block[:4]))  # keep title + meta + desc together
            st.extend(block[4:])                # let remainder flow

        st.append(Spacer(1, 4 * mm))

    return st


def _remediation_roadmap(styles: dict, ai_report: dict) -> list:
    st: list = []
    _section_header(st, styles, "04", "REMEDIATION ROADMAP")

    plans = ai_report.get("remediation_plans") or {}
    phase_map = {
        "CRITICAL": ("Phase 1 — Immediate Action",  "Within 24 hours"),
        "HIGH":     ("Phase 2 — Short-Term",         "Within 1 week"),
        "MEDIUM":   ("Phase 3 — Medium-Term",        "Within 1 month"),
        "LOW":      ("Phase 4 — Long-Term / Ongoing", "Next quarter"),
    }

    if not plans:
        st.append(Paragraph("No remediation plan data available.", styles["body"]))
        return st

    st.append(Paragraph(
        "The following phased remediation roadmap prioritises actions by severity. "
        "Address each phase in order to reduce risk exposure systematically.",
        styles["body"],
    ))
    st.append(Spacer(1, 4 * mm))

    for sev in SEV_ORDER:
        plan = plans.get(sev)
        if not plan:
            continue

        phase_title, timeframe = phase_map.get(sev, (sev, ""))
        sev_col = _sc(sev)

        block: list = []

        # Phase header
        ph_tbl = Table(
            [[
                Paragraph(phase_title, ParagraphStyle(
                    f"ph_{sev}", fontName="Helvetica-Bold", fontSize=11,
                    textColor=sev_col, leading=16,
                )),
                Paragraph(f"Est. {plan.get('estimated_effort', timeframe)}", ParagraphStyle(
                    f"ph_eff_{sev}", fontName="Helvetica", fontSize=9,
                    textColor=SLATE, leading=14, alignment=TA_CENTER,
                )),
            ]],
            colWidths=[120 * mm, PAGE_W - 40 * mm - 120 * mm],
        )
        ph_tbl.setStyle(TableStyle([
            ("LINEBEFORE",    (0, 0), (0, -1), 3, sev_col),
            ("LEFTPADDING",   (0, 0), (0, 0),  8),
            ("VALIGN",        (0, 0), (-1, -1), "MIDDLE"),
            ("TOPPADDING",    (0, 0), (-1, -1), 6),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 6),
            ("BACKGROUND",    (0, 0), (-1, -1), _sbg(sev)),
        ]))
        block.append(ph_tbl)

        summary = plan.get("summary", "")
        if summary:
            block.append(Spacer(1, 2 * mm))
            block.append(Paragraph(summary, styles["find_b"]))

        for j, step in enumerate(plan.get("steps", []), 1):
            block.append(Paragraph(
                f'<font color="{sev_col.hexval()}"><b>{j:02d}.</b></font>  {step}',
                styles["step"],
            ))

        block.append(Spacer(1, 5 * mm))
        st.append(KeepTogether(block[:3]))
        st.extend(block[3:])

    return st


def _cis_compliance(styles: dict, ai_report: dict) -> list:
    st: list = []
    cis_map = ai_report.get("cis_mapping") or {}
    if not cis_map:
        return st

    _section_header(st, styles, "05", "CIS CONTROL COMPLIANCE")

    st.append(Paragraph(
        "The table below maps each CIS control identified during the assessment to its current compliance status.",
        styles["body"],
    ))
    st.append(Spacer(1, 3 * mm))

    sev_rank = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1, "INFO": 0}
    ctrl_keys = sorted(cis_map.keys(), key=lambda k: -sev_rank.get((cis_map[k].get("highest_severity") or "INFO").upper(), 0))

    header = [
        Paragraph("Control", styles["th"]),
        Paragraph("Title",   styles["th"]),
        Paragraph("Status",  styles["th"]),
        Paragraph("Count",   styles["th"]),
        Paragraph("Severity", styles["th"]),
        Paragraph("Note",    styles["th"]),
    ]
    rows = [header]
    for ctrl in ctrl_keys:
        c   = cis_map[ctrl]
        sev = (c.get("highest_severity") or "INFO").upper()
        rows.append([
            Paragraph(ctrl, styles["td_m"]),
            Paragraph(c.get("title", ctrl)[:40], styles["td_b"]),
            Paragraph(c.get("status", "FAIL"), ParagraphStyle(
                f"fail_{ctrl}", fontName="Helvetica-Bold", fontSize=7.5,
                textColor=SEV_C["CRITICAL"], leading=12,
            )),
            Paragraph(str(c.get("findings_count", 0)), styles["td"]),
            _sev_cell(sev, styles),
            Paragraph((c.get("remediation_note") or "—")[:60], styles["td"]),
        ])

    col_w = [22 * mm, 40 * mm, 18 * mm, 14 * mm, 22 * mm, None]
    avail = PAGE_W - 40 * mm - sum(w for w in col_w if w)
    col_w[-1] = avail

    tbl = Table(rows, colWidths=col_w, repeatRows=1)
    tbl.setStyle(TableStyle([
        ("BACKGROUND",    (0, 0), (-1, 0), NAVY),
        ("ROWBACKGROUNDS", (0, 1), (-1, -1), [WHITE, GREY_L]),
        ("TOPPADDING",    (0, 0), (-1, -1), 5),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 5),
        ("LEFTPADDING",   (0, 0), (-1, -1), 6),
        ("RIGHTPADDING",  (0, 0), (-1, -1), 6),
        ("GRID",          (0, 0), (-1, -1), 0.5, GREY_M),
        ("VALIGN",        (0, 0), (-1, -1), "MIDDLE"),
    ]))
    st.append(tbl)
    return st


def _conclusion(styles: dict, findings: list, ai_report: dict) -> list:
    st: list = []
    num = "06" if (ai_report.get("cis_mapping") or {}) else "05"
    _section_header(st, styles, num, "CONCLUSION")

    total    = len(findings)
    critical = sum(1 for f in findings if (f.get("severity") or "").upper() == "CRITICAL")
    high     = sum(1 for f in findings if (f.get("severity") or "").upper() == "HIGH")
    medium   = sum(1 for f in findings if (f.get("severity") or "").upper() == "MEDIUM")
    low      = sum(1 for f in findings if (f.get("severity") or "").upper() == "LOW")
    risk     = ai_report.get("risk_score", 0)

    if critical > 0:
        posture = "critical and requires immediate executive attention"
    elif high > 0:
        posture = "elevated and requires prompt remediation planning"
    elif medium > 0:
        posture = "moderate with clear opportunities for improvement"
    else:
        posture = "generally acceptable with low-severity hardening opportunities"

    st.append(Paragraph(
        f"This automated cloud security assessment identified <b>{total} security findings</b> across the "
        f"target environment. The overall risk posture is <b>{posture}</b>, yielding a risk score of "
        f"<b>{risk} / 100</b>.",
        styles["body"],
    ))
    st.append(Spacer(1, 3 * mm))
    st.append(Paragraph(
        f"Of the findings identified: <b>{critical} critical</b>, <b>{high} high</b>, "
        f"<b>{medium} medium</b>, and <b>{low} low</b> severity issues were discovered. "
        "Critical and high findings should be addressed before any new feature deployment or infrastructure change.",
        styles["body"],
    ))
    st.append(Spacer(1, 4 * mm))
    st.append(Paragraph("Recommended Next Steps", styles["sub_title"]))
    next_steps = [
        "Assign an owner and due date to each critical and high finding.",
        "Establish a recurring scan schedule (weekly for production environments).",
        "Integrate security scanning into the CI/CD pipeline to catch misconfigurations early.",
        "Review and update IAM least-privilege policies across all services.",
        "Enable cloud-native security services (AWS Security Hub, Azure Defender, GCP SCC) for continuous monitoring.",
        "Document accepted risks with business justification and schedule a follow-up review.",
    ]
    for step in next_steps:
        st.append(Paragraph(f"•  {step}", styles["step"]))

    st.append(Spacer(1, 8 * mm))
    st.append(Paragraph(
        "This report was generated automatically by the Multi-Cloud Pentest Platform (MCPP) "
        "with AI-assisted analysis powered by Claude (Anthropic). Results should be validated "
        "by a qualified security engineer before remediation.",
        ParagraphStyle("disc", fontName="Helvetica", fontSize=8, textColor=SLATE, leading=13,
                       borderPad=6, backColor=GREY_L, alignment=TA_JUSTIFY),
    ))
    return st


# ── Public entry point ─────────────────────────────────────────────────────────
def generate_pdf_report(scan_info: dict, findings: list, ai_report: dict) -> bytes:
    """Return PDF bytes for the full pentest report.

    Args:
        scan_info: dict with scan_id, provider, name, etc.
        findings:  list of raw finding dicts from the DB / in-memory state.
        ai_report: dict returned by generate_ai_report() (or the fallback).
    """
    buf = io.BytesIO()
    doc = SimpleDocTemplate(
        buf, pagesize=A4,
        leftMargin=20 * mm, rightMargin=20 * mm,
        topMargin=22 * mm, bottomMargin=18 * mm,
    )

    styles = _make_styles()

    # Count severity for executive summary tiles
    counts = {s: sum(1 for f in findings if (f.get("severity") or "INFO").upper() == s) for s in SEV_ORDER}

    # Sort all findings by severity
    rank = {s: i for i, s in enumerate(SEV_ORDER)}
    findings = sorted(findings, key=lambda f: rank.get((f.get("severity") or "INFO").upper(), 9))

    story: list = []

    # ── Page 1: cover (drawn entirely via canvas in onFirstPage) ───────────────
    story.append(PageBreak())

    # ── Page 2: executive summary ──────────────────────────────────────────────
    story.extend(_exec_summary(styles, ai_report, counts))
    story.append(PageBreak())

    # ── Page 3: risk overview ──────────────────────────────────────────────────
    story.extend(_risk_overview(styles, findings))
    story.append(PageBreak())

    # ── Pages 4+: detailed findings ───────────────────────────────────────────
    story.extend(_detailed_findings(styles, findings, ai_report))
    story.append(PageBreak())

    # ── Remediation roadmap ────────────────────────────────────────────────────
    story.extend(_remediation_roadmap(styles, ai_report))

    # ── CIS compliance ─────────────────────────────────────────────────────────
    if ai_report.get("cis_mapping"):
        story.append(PageBreak())
        story.extend(_cis_compliance(styles, ai_report))

    # ── Conclusion ─────────────────────────────────────────────────────────────
    story.append(PageBreak())
    story.extend(_conclusion(styles, findings, ai_report))

    def _on_first(canvas, doc):
        _draw_cover(canvas, doc, scan_info, ai_report)

    def _on_later(canvas, doc):
        _draw_header_footer(canvas, doc, scan_info)

    doc.build(story, onFirstPage=_on_first, onLaterPages=_on_later)
    return buf.getvalue()
