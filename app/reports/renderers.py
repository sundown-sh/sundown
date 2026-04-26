"""Report renderers: JSON, CSV, HTML, PDF.

PDF rendering uses WeasyPrint when available (Linux/macOS); on Windows
we emit a self-contained HTML file with print-friendly CSS so the
operator can ``Ctrl-P → Save as PDF`` from a browser. Either way the
operator gets an evidence pack styled for an auditor.
"""
from __future__ import annotations

import csv
import io
import json
from dataclasses import asdict
from pathlib import Path
from string import Template
from typing import Literal

from app.reports.data import ReportData


def render_json(data: ReportData) -> bytes:
    payload = {
        "generated_at": data.generated_at.isoformat(),
        "workspace_id": data.workspace_id,
        "scope": data.scope,
        "summary": {
            "total": len(data.rows),
            "by_severity": data.by_severity,
            "by_connector": data.by_connector,
        },
        "ghosts": [asdict(r) for r in data.rows],
    }
    return json.dumps(payload, indent=2, default=str).encode("utf-8")


def render_csv(data: ReportData) -> bytes:
    buf = io.StringIO()
    fieldnames = [
        "ghost_id",
        "severity",
        "state",
        "days_since_termination",
        "person_name",
        "person_email",
        "employee_number",
        "termination_date",
        "connector",
        "integration_name",
        "account_external_id",
        "account_username",
        "account_email",
        "last_login_at",
        "match_rule",
        "match_confidence",
        "first_seen_at",
        "last_seen_at",
        "notes",
    ]
    w = csv.DictWriter(buf, fieldnames=fieldnames, extrasaction="ignore")
    w.writeheader()
    for r in data.rows:
        d = asdict(r)
        d.pop("match_evidence", None)
        w.writerow(d)
    return buf.getvalue().encode("utf-8")


# NOTE: this template uses ``string.Template`` (``$name`` placeholders) on
# purpose. ``str.format`` would choke on every literal ``{`` and ``}`` in
# the embedded CSS, so we keep the CSS readable and use ``$`` for our own
# fields. Any literal dollar sign in CSS would need to be written as ``$$``.
_HTML_TEMPLATE = Template("""<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8" />
  <title>Sundown — Ghost Account Report</title>
  <style>
    @page { size: Letter; margin: 0.6in; }
    * { box-sizing: border-box; }
    body {
      font-family: -apple-system, "Segoe UI", Roboto, Helvetica, Arial, sans-serif;
      color: #1f2937; margin: 0; padding: 0; line-height: 1.45;
    }
    header { border-bottom: 2px solid #f59e0b; padding-bottom: 14px; margin-bottom: 24px; }
    h1 { margin: 0 0 6px 0; font-size: 24px; }
    .subtitle { color: #6b7280; font-size: 13px; }
    h2 { margin-top: 28px; font-size: 16px; border-bottom: 1px solid #e5e7eb; padding-bottom: 4px; }
    .grid { display: grid; grid-template-columns: 1fr 1fr 1fr; gap: 12px; margin: 12px 0 0 0; }
    .stat { padding: 10px 12px; border: 1px solid #e5e7eb; border-radius: 6px; }
    .stat .n { font-size: 20px; font-weight: 600; }
    .stat .l { font-size: 11px; color: #6b7280; text-transform: uppercase; letter-spacing: 0.04em; }
    table { width: 100%; border-collapse: collapse; font-size: 11px; margin-top: 8px; }
    th, td { padding: 6px 8px; text-align: left; border-bottom: 1px solid #f3f4f6; vertical-align: top; }
    th { background: #f9fafb; font-weight: 600; font-size: 10px; text-transform: uppercase; letter-spacing: 0.04em; color: #6b7280; }
    .badge { display: inline-block; padding: 1px 6px; border-radius: 4px; font-size: 10px; font-weight: 600; }
    .sev-critical { background: #fee2e2; color: #991b1b; }
    .sev-high     { background: #fef3c7; color: #92400e; }
    .sev-medium   { background: #dbeafe; color: #1e40af; }
    .meth { font-size: 12px; color: #374151; }
    .meth ol { padding-left: 18px; }
    footer { margin-top: 36px; padding-top: 14px; border-top: 1px solid #e5e7eb; font-size: 11px; color: #6b7280; }
    .sig { margin-top: 24px; display: grid; grid-template-columns: 1fr 1fr; gap: 24px; }
    .sig div { border-top: 1px solid #9ca3af; padding-top: 6px; font-size: 11px; }
  </style>
</head>
<body>
  <header>
    <h1>Sundown — Ghost Account Report</h1>
    <div class="subtitle">
      Generated $generated_at · Workspace <code>$workspace_id</code> ·
      Sundown $sundown_version (open source, read-only)
    </div>
  </header>

  <h2>Summary</h2>
  <div class="grid">
    <div class="stat"><div class="n">$total</div><div class="l">Open ghosts</div></div>
    <div class="stat"><div class="n">$critical</div><div class="l">Critical (&gt;7 days)</div></div>
    <div class="stat"><div class="n">$high</div><div class="l">High (24h&ndash;7d)</div></div>
  </div>

  <h2>Scope</h2>
  <div class="meth">
    $scope_html
  </div>

  <h2>Methodology</h2>
  <div class="meth">
    <p>Sundown cross-references HRIS terminations against active accounts in
    every connected destination. Detection is read-only — Sundown holds
    no credentials with write scopes on any connected system.</p>
    <p>An account is reported as a <em>ghost</em> when an explainable rule
    chain matches it to a person whose HRIS status is <code>terminated</code>.
    Rules, in priority order:</p>
    <ol>
      <li><b>email</b> — primary work email, exact (case-insensitive)</li>
      <li><b>alias</b> — any HRIS alias matches account email or alias</li>
      <li><b>sso_subject</b> — HRIS SSO subject equals account.sso_subject</li>
      <li><b>fuzzy</b> — Levenshtein &le; 2 on email local-part with same domain
        (only if the destination exposes a name and there is exactly one candidate)</li>
    </ol>
    <p>Severity is derived purely from days since termination:
      <span class="badge sev-critical">critical</span> &gt; 7 days,
      <span class="badge sev-high">high</span> 24h&ndash;7 days,
      <span class="badge sev-medium">medium</span> &lt; 24 hours.</p>
  </div>

  <h2>Findings ($total)</h2>
  <table>
    <thead>
      <tr>
        <th>Sev.</th>
        <th>Person</th>
        <th>Term&nbsp;date</th>
        <th title="Days since the employee was marked terminated in HRIS">Days&nbsp;since&nbsp;term.</th>
        <th>Destination</th>
        <th>Account</th>
        <th>Rule</th>
        <th>Last login</th>
      </tr>
    </thead>
    <tbody>
$rows_html
    </tbody>
  </table>

  <div class="sig">
    <div>Reviewed by &mdash; signature</div>
    <div>Date</div>
  </div>

  <footer>
    Report ID: <code>$report_id</code> ·
    Sundown <code>$sundown_version</code> ·
    This file is generated by Sundown, an Apache-2.0 open-source tool.
    The findings above are produced from the data collected at generation
    time; re-run Sundown for current state. No accounts were modified
    during the production of this report.
  </footer>
</body>
</html>
""")


def render_html(data: ReportData, *, report_id: str = "—") -> bytes:
    from app import __version__

    rows = []
    for r in data.rows:
        rows.append(
            "      <tr>"
            f"<td><span class='badge sev-{r.severity}'>{r.severity}</span></td>"
            f"<td><b>{_e(r.person_name)}</b><br><span style='color:#6b7280'>{_e(r.person_email)}</span></td>"
            f"<td>{r.termination_date or '—'}</td>"
            f"<td>{r.days_since_termination}</td>"
            f"<td><b>{_e(_connector_label(r.connector))}</b><br><span style='color:#6b7280'>{_e(r.integration_name)}</span></td>"
            f"<td>{_e(r.account_username or r.account_email or r.account_external_id)}</td>"
            f"<td>{_e(r.match_rule)} <span style='color:#9ca3af'>({_e(r.match_confidence)})</span></td>"
            f"<td>{_short_date(r.last_login_at)}</td>"
            "</tr>"
        )
    summary = data.by_severity
    scope_html = (
        f"<pre style='background:#f9fafb;padding:8px;border-radius:6px;'>{_e(json.dumps(data.scope, indent=2) or '{}')}</pre>"
    )
    html = _HTML_TEMPLATE.substitute(
        generated_at=data.generated_at.strftime("%Y-%m-%d %H:%M UTC"),
        workspace_id=_e(data.workspace_id),
        total=len(data.rows),
        critical=summary.get("critical", 0),
        high=summary.get("high", 0),
        scope_html=scope_html,
        rows_html="\n".join(rows) if rows else "<tr><td colspan='8' style='text-align:center;color:#9ca3af;padding:18px'>No ghosts in scope.</td></tr>",
        report_id=report_id,
        sundown_version=__version__,
    )
    return html.encode("utf-8")


def render_pdf(
    data: ReportData, *, report_id: str = "—"
) -> tuple[bytes, Literal["pdf", "html"]]:
    """Try WeasyPrint first; return real PDF bytes. If WeasyPrint is
    unavailable (typical on Windows, where we do not ship the dependency),
    return the same **print-styled HTML** as ``render_html`` and tag it as
    ``\"html\"`` so the service stores ``.html`` + ``text/html`` — never a
    fake ``.pdf`` file (browsers cannot open HTML as PDF).
    """
    html = render_html(data, report_id=report_id)
    try:
        from weasyprint import HTML

        pdf_bytes = HTML(string=html.decode("utf-8")).write_pdf()
        if pdf_bytes:
            return pdf_bytes, "pdf"
    except Exception:
        pass
    return html, "html"


def write_to_path(content: bytes, path: Path) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(content)
    return path


# --- helpers --------------------------------------------------------------


def _e(s: str | None) -> str:
    if s is None:
        return ""
    return (
        s.replace("&", "&amp;")
        .replace("<", "&lt;")
        .replace(">", "&gt;")
        .replace('"', "&quot;")
    )


def _short_date(iso: str | None) -> str:
    if not iso:
        return "—"
    return iso[:10]


def _connector_label(slug: str) -> str:
    """Humanize a connector slug (``okta`` → ``Okta``, ``bamboohr`` → ``BambooHR``)."""
    if not slug:
        return "—"
    overrides = {
        "bamboohr": "BambooHR",
        "github": "GitHub",
        "google_workspace": "Google Workspace",
        "okta": "Okta",
        "slack": "Slack",
        "rippling": "Rippling",
    }
    return overrides.get(slug, slug.replace("_", " ").title())
