"""PDF report: executive summary followed by every finding. Pure function of the scan data."""
from __future__ import annotations

import io
import textwrap
from datetime import datetime, timezone
from xml.sax.saxutils import escape

from reportlab.lib import colors
from reportlab.lib.enums import TA_LEFT
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.lib.units import mm
from reportlab.platypus import (
    CondPageBreak,
    KeepTogether,
    PageBreak,
    Paragraph,
    Preformatted,
    SimpleDocTemplate,
    Spacer,
    Table,
    TableStyle,
)

from .summary import SEVERITIES, risk_level

NAVY = colors.HexColor("#14213D")
TEAL = colors.HexColor("#0B5F66")
MUTED = colors.HexColor("#5B6578")
BORDER = colors.HexColor("#DDE2EA")
SEV_BG = {
    "Critical": colors.HexColor("#7A1626"),
    "High": colors.HexColor("#C2410C"),
    "Medium": colors.HexColor("#F5C451"),
    "Low": colors.HexColor("#DCE6F2"),
}
SEV_FG = {"Critical": colors.white, "High": colors.white,
          "Medium": colors.HexColor("#3d2c00"), "Low": colors.HexColor("#22324a")}
CHECK_LABELS = {"code": "Code flaws (Semgrep)", "deps": "Vulnerable dependencies (Trivy)",
                "secrets": "Hardcoded secrets (Gitleaks)", "iac": "Docker and Terraform (Trivy config)",
                "web": "Web security checks", "nuclei": "Known vulnerabilities (Nuclei)",
                "authz": "Access control comparison", "zap": "OWASP ZAP (crawl, passive)",
                "zap_active": "OWASP ZAP active scan", "tls": "TLS protocols and ciphers",
                "ports": "Open ports and services",
                "ai": "AI review (Claude)"}
SNIPPET_WIDTH = 100
MAX_SNIPPET_LINES = 20

_base = getSampleStyleSheet()
S = {
    "title": ParagraphStyle("t", parent=_base["Title"], fontName="Helvetica-Bold", fontSize=20,
                            textColor=NAVY, alignment=TA_LEFT, spaceAfter=2),
    "sub": ParagraphStyle("s", parent=_base["Normal"], fontSize=9, textColor=MUTED, leading=12),
    "h1": ParagraphStyle("h1", parent=_base["Heading1"], fontName="Helvetica-Bold", fontSize=14,
                         textColor=NAVY, spaceBefore=10, spaceAfter=6),
    "h2": ParagraphStyle("h2", parent=_base["Heading2"], fontName="Helvetica-Bold", fontSize=11,
                         textColor=NAVY, spaceBefore=4, spaceAfter=3, leading=14),
    "label": ParagraphStyle("l", parent=_base["Normal"], fontName="Helvetica-Bold", fontSize=8.5,
                            textColor=TEAL, spaceBefore=5, spaceAfter=1),
    "body": ParagraphStyle("b", parent=_base["Normal"], fontSize=9, leading=12.5),
    "small": ParagraphStyle("sm", parent=_base["Normal"], fontSize=8, leading=10.5, textColor=MUTED),
    "mono": ParagraphStyle("m", parent=_base["Code"], fontName="Courier", fontSize=7.5, leading=9.5,
                           backColor=colors.HexColor("#F1F3F6"), borderPadding=5, leftIndent=5,
                           rightIndent=5, spaceBefore=4, spaceAfter=4),
    "cell": ParagraphStyle("c", parent=_base["Normal"], fontSize=8.5, leading=11),
}


def _p(text, style="body") -> Paragraph:
    """Paragraph from untrusted text: escaped, newlines kept."""
    return Paragraph(escape(str(text or "")).replace("\n", "<br/>"), S[style])


def _fmt_time(value) -> str:
    if not value:
        return "-"
    if isinstance(value, str):
        return value
    if value.tzinfo is None:
        value = value.replace(tzinfo=timezone.utc)
    return value.astimezone(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")


def _wrap_snippet(snippet: str) -> str:
    out = []
    for line in (snippet or "").splitlines()[:MAX_SNIPPET_LINES]:
        out.extend(textwrap.wrap(line, SNIPPET_WIDTH, replace_whitespace=False, drop_whitespace=False,
                                 subsequent_indent="    ") or [""])
    return "\n".join(out)


def _sev_cell(sev: str) -> Table:
    t = Table([[sev]], colWidths=[17 * mm], rowHeights=[5 * mm])
    t.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, -1), SEV_BG.get(sev, BORDER)),
        ("TEXTCOLOR", (0, 0), (-1, -1), SEV_FG.get(sev, colors.black)),
        ("FONTNAME", (0, 0), (-1, -1), "Helvetica-Bold"),
        ("FONTSIZE", (0, 0), (-1, -1), 7.5),
        ("ALIGN", (0, 0), (-1, -1), "CENTER"),
        ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
        ("TOPPADDING", (0, 0), (-1, -1), 0),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 1),
    ]))
    return t


def severity_bar(counts: dict, width: float) -> Table | None:
    """Stacked horizontal bar, one segment per severity, proportional to the counts."""
    present = [(s, counts.get(s, 0)) for s in SEVERITIES if counts.get(s, 0)]
    total = sum(n for _, n in present)
    if not total:
        return None
    widths = [max(width * n / total, 9 * mm) for _, n in present]
    scale = width / sum(widths)
    widths = [w * scale for w in widths]
    t = Table([[str(n) for _, n in present]], colWidths=widths, rowHeights=[7 * mm])
    style = [("ALIGN", (0, 0), (-1, -1), "CENTER"), ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
             ("FONTNAME", (0, 0), (-1, -1), "Helvetica-Bold"), ("FONTSIZE", (0, 0), (-1, -1), 9)]
    for i, (s, _) in enumerate(present):
        style += [("BACKGROUND", (i, 0), (i, 0), SEV_BG[s]), ("TEXTCOLOR", (i, 0), (i, 0), SEV_FG[s])]
    t.setStyle(TableStyle(style))
    return t


def _summary_text(counts: dict, total: int, project_name: str) -> str:
    if not total:
        return (f"No security findings were reported for {project_name} by the checks that ran. "
                "This does not prove the code is free of vulnerabilities; it means none of the "
                "enabled automated checks matched.")
    risk = risk_level(counts)
    parts = [f"{counts.get(s, 0)} {s}" for s in SEVERITIES if counts.get(s, 0)]
    text = (f"The scan of {project_name} reported {total} finding(s): {', '.join(parts)}. "
            f"The overall risk level is <b>{risk}</b>, the highest severity found. ")
    if counts.get("Critical") or counts.get("High"):
        text += ("Critical and High findings can typically be exploited to compromise data, "
                 "accounts or infrastructure and should be fixed before the next release. ")
    text += "Each finding below lists the location, what is wrong, how it could be exploited and a recommended fix."
    return text


def _top_table(findings: list[dict], width: float) -> Table:
    rows = [[Paragraph("<b>Severity</b>", S["cell"]), Paragraph("<b>Finding</b>", S["cell"]),
             Paragraph("<b>Location</b>", S["cell"])]]
    for f in findings:
        loc = f["file_path"] + (f":{f['line']}" if f.get("line") else "")
        rows.append([_sev_cell(f["severity"]), _p(f["title"], "cell"), _p(loc, "cell")])
    t = Table(rows, colWidths=[20 * mm, width * 0.5, width - 20 * mm - width * 0.5], repeatRows=1)
    t.setStyle(TableStyle([
        ("LINEBELOW", (0, 0), (-1, -1), 0.4, BORDER),
        ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
        ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#F1F3F6")),
        ("TOPPADDING", (0, 0), (-1, -1), 3), ("BOTTOMPADDING", (0, 0), (-1, -1), 3),
    ]))
    return t


def _finding_block(i: int, f: dict, width: float) -> list:
    loc = f["file_path"] + (f":{f['line']}" if f.get("line") else "")
    head = Table([[_sev_cell(f["severity"]), _p(f"{i}. {f['title']}", "h2")]],
                 colWidths=[20 * mm, width - 20 * mm])
    head.setStyle(TableStyle([("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
                              ("LEFTPADDING", (0, 0), (-1, -1), 0)]))
    meta = [f"Location: {loc}"]
    if f.get("cvss_score") is not None:
        meta.append(f"CVSS {f['cvss_score']:.1f}" + (" (estimated)" if f.get("cvss_source") == "estimated"
                                                     else f" {f.get('cvss_vector') or ''}".rstrip()))
    if f.get("status") and f["status"] != "open":
        meta.append("Status: " + f["status"].replace("_", " ").capitalize())
    if f.get("is_new") is False:
        meta.append("Seen in the previous scan")
    if f.get("cwe"):
        meta.append(f"CWE: {f['cwe']}")
    if f.get("owasp"):
        meta.append(f"OWASP: {f['owasp']}")
    meta.append("Found by: " + ", ".join(f.get("scanners") or []))
    if f.get("rule_id"):
        meta.append(f"Rule: {f['rule_id']}")
    if f.get("ai_verdict"):
        meta.append(f"AI review: {f['ai_verdict']}")
    block = [head, _p("  |  ".join(meta), "small")]
    if f.get("snippet"):
        block += [_p("Code", "label"), Preformatted(_wrap_snippet(f["snippet"]), S["mono"])]
    if f.get("status_note"):
        block += [_p("Status note", "label"), _p(f["status_note"])]
    for label, key in (("What is wrong", "description"), ("How it could be exploited", "exploitation"),
                       ("Recommended fix", "recommendation"), ("AI notes", "ai_notes")):
        if f.get(key):
            block += [_p(label, "label"), _p(f[key])]
    return [CondPageBreak(45 * mm), KeepTogether(block[:3]), *block[3:], Spacer(1, 4 * mm)]


def build_pdf(scan: dict, findings: list[dict]) -> bytes:
    """scan: dict with project/branch/commit_sha/created_at/finished_at/languages/frameworks/
    counts/checks/notes/ai_summary. findings: finding dicts, already sorted by severity."""
    buf = io.BytesIO()
    project = scan["project"]
    suppressed = [f for f in findings if f.get("status") in ("false_positive", "accepted_risk")]
    findings = [f for f in findings if f.get("status") not in ("false_positive", "accepted_risk")]
    doc = SimpleDocTemplate(buf, pagesize=A4, leftMargin=16 * mm, rightMargin=16 * mm,
                            topMargin=16 * mm, bottomMargin=16 * mm,
                            title=f"Security report - {project['name']}", author="VAPT Scanner")
    width = doc.width
    counts = {s: (scan.get("counts") or {}).get(s, 0) for s in SEVERITIES}
    total = sum(counts.values())
    generated = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")

    def footer(canvas, d):
        canvas.saveState()
        canvas.setFont("Helvetica", 7.5)
        canvas.setFillColor(MUTED)
        canvas.drawString(16 * mm, 9 * mm, f"VAPT Scanner - {project['name'][:80]} - scan #{scan['id']}")
        canvas.drawRightString(A4[0] - 16 * mm, 9 * mm, f"Page {d.page}")
        canvas.restoreState()

    story: list = [
        Paragraph("Security scan report", S["title"]),
        _p(f"Generated {generated}. Confidential: contains details of security weaknesses.", "sub"),
        Spacer(1, 5 * mm),
    ]

    langs = ", ".join(l["name"] if isinstance(l, dict) else str(l) for l in scan.get("languages") or []) or "-"
    checks = ", ".join(CHECK_LABELS.get(k, k) for k, v in (scan.get("checks") or {}).items() if v) or "-"
    commit = (scan.get("commit_sha") or "")[:12] or "-"
    info = [
        ("Project", project["name"]), ("Source", project.get("source")),
        ("Branch", scan.get("branch") or "-"), ("Commit", commit),
        ("Scan started", _fmt_time(scan.get("started_at") or scan.get("created_at"))),
        ("Scan finished", _fmt_time(scan.get("finished_at"))),
        ("Languages", langs), ("Frameworks", ", ".join(scan.get("frameworks") or []) or "-"),
        ("Checks run", checks),
    ]
    t = Table([[_p(k, "cell"), _p(v, "cell")] for k, v in info], colWidths=[32 * mm, width - 32 * mm])
    t.setStyle(TableStyle([
        ("LINEBELOW", (0, 0), (-1, -1), 0.4, BORDER),
        ("TEXTCOLOR", (0, 0), (0, -1), MUTED),
        ("VALIGN", (0, 0), (-1, -1), "TOP"),
        ("TOPPADDING", (0, 0), (-1, -1), 2.5), ("BOTTOMPADDING", (0, 0), (-1, -1), 2.5),
    ]))
    story += [t, Paragraph("Executive summary", S["h1"]),
              Paragraph(_summary_text(counts, total, escape(project["name"])), S["body"]), Spacer(1, 4 * mm)]

    bar = severity_bar(counts, width)
    if bar:
        story += [bar, Spacer(1, 2 * mm)]
    legend = Table([[f"{s}: {counts[s]}" for s in SEVERITIES]], colWidths=[width / 4] * 4)
    legend.setStyle(TableStyle([("FONTSIZE", (0, 0), (-1, -1), 8.5), ("TEXTCOLOR", (0, 0), (-1, -1), MUTED),
                                ("LEFTPADDING", (0, 0), (-1, -1), 0)]))
    story += [legend]

    diff = scan.get("diff") or {}
    if diff.get("previous_scan_id"):
        story += [Paragraph("Changes since the previous scan", S["h2"]),
                  _p(f"Compared with scan #{diff['previous_scan_id']}: {diff.get('new', 0)} new finding(s), "
                     f"{diff.get('recurring', 0)} still present, {diff.get('fixed', 0)} no longer found.")]
        for it in (diff.get("fixed_items") or [])[:15]:
            story.append(_p(f"- Fixed: [{it['severity']}] {it['title']} ({it['file_path']})", "small"))
    if suppressed:
        story += [_p(f"{len(suppressed)} finding(s) marked as false positive or accepted risk are left out of "
                     "this report's counts and details.", "small")]
    if scan.get("ai_summary"):
        story += [Paragraph("AI review summary", S["h2"]), _p(scan["ai_summary"])]
    if scan.get("notes"):
        story += [Paragraph("Scan notes", S["h2"])] + [_p(f"- {n}", "small") for n in scan["notes"]]

    if findings:
        story += [Paragraph("Findings overview", S["h1"]), _top_table(findings, width),
                  PageBreak(), Paragraph("Findings in detail", S["h1"])]
        for i, f in enumerate(findings, 1):
            story += _finding_block(i, f, width)

    doc.build(story, onFirstPage=footer, onLaterPages=footer)
    return buf.getvalue()
