"""Report rendering.

One report dict goes in, and four shapes come out: a console summary, JSON,
Markdown, and a self-contained HTML page. The formats are separate renderers
over the same data, so a section added for one is added for all.

Output is deterministic: every list is sorted and every mapping is emitted in a
fixed order, so two runs against an unchanged target differ only in the
timestamp and duration.
"""

from __future__ import annotations

import html
import json
from io import StringIO
from typing import Any

from .context import ReconContext

__all__ = [
    "FORMATS",
    "console",
    "markdown",
    "render",
    "to_html",
    "to_json",
]

#: Formats the CLI accepts.
FORMATS: tuple[str, ...] = ("text", "json", "md", "html")

#: Printed at the end of every human-facing report.
_NOTICE = (
    "Passive reconnaissance only. Use ReconX on domains you own or are "
    "explicitly authorized to test."
)

#: Base styling for the HTML report. Inlined so a single file can be attached
#: to a ticket or emailed without losing its formatting.
_CSS = """
:root {
  --bg: #12151b; --panel: #1a1f28; --line: #2b323d;
  --fg: #e6e9ef; --dim: #97a0b0; --accent: #6ea8fe; --warn: #f0b429; --bad: #ef6b73;
  --good: #59c98a;
}
* { box-sizing: border-box; }
body {
  margin: 0; padding: 2.5rem 1.5rem; background: var(--bg); color: var(--fg);
  font: 15px/1.6 ui-sans-serif, system-ui, -apple-system, "Segoe UI", Roboto, sans-serif;
}
.wrap { max-width: 60rem; margin: 0 auto; }
h1 { font-size: 1.6rem; margin: 0 0 .25rem; letter-spacing: -.01em; }
h2 {
  font-size: 1.05rem; margin: 2rem 0 .75rem; padding-bottom: .4rem;
  border-bottom: 1px solid var(--line); text-transform: uppercase;
  letter-spacing: .06em; color: var(--dim);
}
.sub { color: var(--dim); font-size: .875rem; margin: 0 0 1.5rem; }
.meta { display: flex; flex-wrap: wrap; gap: .5rem; margin-bottom: .5rem; }
.pill {
  background: var(--panel); border: 1px solid var(--line); border-radius: 999px;
  padding: .15rem .7rem; font-size: .8rem; color: var(--dim);
}
.pill b { color: var(--fg); font-weight: 600; }
table { width: 100%; border-collapse: collapse; margin: .25rem 0 1rem; }
th, td {
  text-align: left; padding: .5rem .65rem; border-bottom: 1px solid var(--line);
  vertical-align: top; font-size: .875rem;
}
th { color: var(--dim); font-weight: 600; width: 34%; }
td.mono, .mono {
  font-family: ui-monospace, SFMono-Regular, Menlo, Consolas, monospace;
  font-size: .8125rem; word-break: break-word;
}
.ok { color: var(--good); } .warn { color: var(--warn); } .bad { color: var(--bad); }
.notice {
  border: 1px solid var(--line); border-left: 3px solid var(--warn);
  background: var(--panel); border-radius: 6px; padding: .75rem 1rem;
  color: var(--dim); font-size: .8125rem; margin: 1.5rem 0 0;
}
footer { color: var(--dim); font-size: .75rem; margin-top: 2.5rem; }
"""


def _escape(value: Any) -> str:
    """HTML-escape a value, rendering containers readably.

    Nested records (MX, SOA) are flattened to ``key=value`` rather than
    rendered as a Python dict literal.
    """
    if isinstance(value, dict):
        return ", ".join(f"{key}={_escape(item)}" for key, item in value.items()) or "-"
    if isinstance(value, (list, tuple)):
        return ", ".join(_escape(item) for item in value) if value else "-"
    return html.escape(str(value))


def to_json(report: dict[str, Any]) -> str:
    """Render the report as indented, key-sorted JSON.

    Args:
        report: A report dict from :func:`reconx.core.run`.

    Returns:
        A JSON document. ``default=str`` guarantees serialisation even if a
        module ever returns a value JSON does not understand.
    """
    return json.dumps(report, indent=2, sort_keys=True, default=str)


def _kv_rows(data: dict[str, Any], skip: set[str]) -> list[tuple[str, Any]]:
    """Return the renderable key/value pairs of a module result."""
    return [(key, value) for key, value in sorted(data.items()) if key not in skip]


def _section_body(name: str, data: dict[str, Any]) -> dict[str, Any]:
    """Reduce a module result to what a report actually displays.

    Verbose internals (per-attempt logs, raw header dictionaries) are already
    visible in the JSON output, so the human-facing formats show the fields
    worth reading instead of dumping everything.
    """
    common = {"duration_seconds", "error", "warnings", "attempts"}

    if name == "dns":
        return {"rows": [], "lists": dict(sorted((data.get("records", {}) or {}).items()))}
    if name == "http":
        audit = data.get("security_headers", {}) or {}
        return {
            "rows": [
                ("final url", data.get("final_url", "-")),
                ("status", f"{data.get('status_code', '-')} {data.get('reason', '')}".strip()),
                ("response time", f"{data.get('response_time_ms', '-')} ms"),
                ("redirects", data.get("redirect_count", 0)),
                (
                    "security headers",
                    f"{audit.get('score', 0)}/{audit.get('total', 0)}"
                    f" (grade {audit.get('grade', '-')})",
                ),
            ],
            "missing": audit.get("missing", []),
        }
    if name == "tls":
        return {
            "rows": [
                ("subject", data.get("subject", "-")),
                ("issuer", data.get("issuer", "-")),
                ("valid until", data.get("not_after", "-")),
                (
                    "days to expiry",
                    data.get("days_until_expiry")
                    if data.get("days_until_expiry") is not None
                    else "-",
                ),
                ("protocol", data.get("protocol", "-")),
                ("cipher", data.get("cipher", "-")),
            ],
            "lists": {
                "subject alternative names": data.get("subject_alt_names", []),
            },
        }
    if name == "tech":
        techs = data.get("technologies", []) or []
        return {
            "rows": [("generator", data.get("generator") or "-")],
            "lists": {
                "technologies": [
                    f"{item['name']} ({item['category']}, {item['confidence']})" for item in techs
                ]
            },
        }
    if name == "subdomains":
        found = data.get("subdomains", []) or []
        return {
            "rows": [
                ("found", len(found)),
                (
                    "sources",
                    ", ".join(
                        f"{key}={value}" for key, value in sorted(data.get("sources", {}).items())
                    ),
                ),
                ("wildcard dns", data.get("wildcard_dns", False)),
            ],
            "lists": {"subdomains": found},
        }
    if name == "whois":
        order = (
            "registrar",
            "registrant",
            "organization",
            "created",
            "updated",
            "expires",
            "name_servers",
            "status",
            "country",
            "emails",
            "dnssec",
        )
        rows = [
            (key, data[key])
            for key in order
            if key in data and data[key] not in (None, "", [])
        ]
        rows.extend(
            (key, value)
            for key, value in sorted(data.items())
            if key not in order and key not in common
        )
        return {"rows": rows, "lists": {}}
    return {"rows": _kv_rows(data, common), "lists": {}}


def markdown(report: dict[str, Any]) -> str:
    """Render the report as Markdown.

    Args:
        report: A report dict from :func:`reconx.core.run`.

    Returns:
        A Markdown document, suitable for pasting into a write-up.
    """
    lines: list[str] = [
        f"# ReconX report: {report['target']}",
        "",
        f"- **Tool:** ReconX {report['version']}",
        f"- **Generated:** {report['generated_at']}",
        f"- **Duration:** {report['duration_seconds']}s",
        f"- **Modules:** {', '.join(report['modules'])}",
        "",
    ]

    for name in report["modules"]:
        data = report["results"][name]
        lines.append(f"## {name}")
        lines.append("")
        if "error" in data:
            lines.append(f"**Failed:** {data['error']}")
            lines.append("")
            continue

        section = _section_body(name, data)
        for label, value in section["rows"]:
            lines.append(f"- **{label}:** {_md_value(value)}")
        for label, values in section.get("lists", {}).items():
            if not values:
                continue
            lines.append(f"- **{label}:** {_md_value(values)}")
        for warning in data.get("warnings", []) or []:
            lines.append(f"- _warning:_ {warning}")
        lines.append("")

    lines.append("---")
    lines.append("")
    lines.append(f"_{_NOTICE}_")
    return "\n".join(lines) + "\n"


def _md_value(value: Any) -> str:
    """Render a value for the Markdown report."""
    if isinstance(value, dict):
        return ", ".join(f"{key}={item}" for key, item in value.items()) or "-"
    if isinstance(value, (list, tuple)):
        if not value:
            return "-"
        # MX and SOA records are dicts inside a list; printing Python repr
        # there leaks braces and quotes into a document meant for humans.
        return ", ".join(_md_value(item) for item in value)
    if value is None or value == "":
        return "-"
    return str(value)


def to_html(report: dict[str, Any]) -> str:
    """Render the report as a single self-contained HTML page.

    Args:
        report: A report dict from :func:`reconx.core.run`.

    Returns:
        A complete HTML document with inline CSS and no external assets, so it
        renders identically offline and can be attached to a ticket as-is.
    """
    summary = report.get("summary", {}) or {}
    failed = set(summary.get("modules_failed", []) or [])

    parts: list[str] = [
        "<!DOCTYPE html>",
        '<html lang="en"><head><meta charset="utf-8">',
        '<meta name="viewport" content="width=device-width, initial-scale=1">',
        f"<title>ReconX report: {html.escape(report['target'])}</title>",
        f"<style>{_CSS}</style></head><body><div class='wrap'>",
        f"<h1>ReconX report: {html.escape(report['target'])}</h1>",
        f"<p class='sub'>Generated {html.escape(report['generated_at'])} "
        f"in {report['duration_seconds']}s</p>",
        "<div class='meta'>",
        f"<span class='pill'>ReconX <b>{html.escape(report['version'])}</b></span>",
        f"<span class='pill'>Modules <b>{len(report['modules'])}</b></span>",
        f"<span class='pill'>Failed <b class='{'bad' if failed else 'ok'}'>"
        f"{len(failed)}</b></span>",
        f"<span class='pill'>Warnings <b>{summary.get('warning_count', 0)}</b></span>",
        "</div>",
    ]

    for name in report["modules"]:
        data = report["results"][name]
        parts.append(f"<h2>{html.escape(name)}</h2>")
        if "error" in data:
            parts.append(f"<p class='bad'>{_escape(data['error'])}</p>")
            continue

        section = _section_body(name, data)
        parts.append("<table>")
        for label, value in section["rows"]:
            parts.append(f"<tr><th>{html.escape(str(label))}</th><td>{_escape(value)}</td></tr>")
        parts.append("</table>")

        for label, values in section.get("lists", {}).items():
            if not values:
                continue
            items = "".join(f"<li>{_escape(item)}</li>" for item in values)
            parts.append(f"<p class='sub'>{html.escape(label)}</p><ul>{items}</ul>")

        missing = section.get("missing") or []
        if missing:
            parts.append(
                f"<p class='warn'>Missing security headers: {_escape(', '.join(missing))}</p>"
            )

        warnings = data.get("warnings", []) or []
        if warnings:
            items = "".join(f"<li>{_escape(item)}</li>" for item in warnings)
            parts.append(f"<p class='sub'>warnings</p><ul>{items}</ul>")

    parts.append(
        f"<p class='notice'>{html.escape(_NOTICE)} A failing module records an "
        "error and does not affect the others.</p>"
        f"<footer>ReconX {html.escape(report['version'])}</footer>"
        "</div></body></html>"
    )
    return "\n".join(parts) + "\n"


def console(report: dict[str, Any], context: ReconContext | None = None) -> str:
    """Render the default terminal summary.

    Uses ``rich`` when it is installed for colour and box drawing, and falls
    back to plain text when it is not, so the optional extra stays optional.

    Args:
        report: A report dict from :func:`reconx.core.run`.
        context: Unused; accepted so the signature matches the other renderers.

    Returns:
        A string suitable for printing.
    """
    del context
    try:
        return _console_rich(report)
    except ImportError:
        return _console_plain(report)


def _console_rich(report: dict[str, Any]) -> str:
    """Render the summary with ``rich``."""
    from rich.console import Console
    from rich.panel import Panel
    from rich.table import Table

    # Recording into a StringIO rather than stdout: the rendered text is
    # returned, so printing it would duplicate the whole summary.
    buffer = StringIO()
    console_ = Console(file=buffer, record=True, width=100, force_terminal=False)
    summary = report.get("summary", {}) or {}

    console_.print(
        Panel.fit(
            f"[bold]{report['target']}[/bold]  "
            f"[dim]{report['generated_at']} - {report['duration_seconds']}s[/dim]",
            title=f"ReconX {report['version']}",
            border_style="blue",
        )
    )

    for name in report["modules"]:
        data = report["results"][name]
        if "error" in data:
            console_.print(f"[bold red]{name}[/bold red] [red]{data['error']}[/red]")
            continue

        table = Table(show_header=False, box=None, padding=(0, 1))
        table.add_column(style="cyan", no_wrap=True)
        table.add_column(overflow="fold")

        section = _section_body(name, data)
        for label, value in section["rows"]:
            table.add_row(str(label), _console_value(value))
        for label, values in section.get("lists", {}).items():
            if values:
                table.add_row(label, _console_value(values))
        missing = section.get("missing") or []
        if missing:
            table.add_row("missing headers", f"[yellow]{', '.join(missing)}[/yellow]")
        for warning in data.get("warnings", []) or []:
            table.add_row("[yellow]warning[/yellow]", f"[yellow]{warning}[/yellow]")

        console_.print(f"[bold blue]{name}[/bold blue]")
        console_.print(table)

    failed = summary.get("modules_failed") or []
    if failed:
        console_.print(f"[red]modules with errors:[/red] {', '.join(failed)}")
    else:
        console_.print(f"[green]all {summary.get('modules_run', 0)} module(s) completed[/green]")

    console_.print(f"[dim]{_NOTICE}[/dim]")
    return console_.export_text()


def _console_value(value: Any) -> str:
    """Render a value for the console summary."""
    if isinstance(value, dict):
        return ", ".join(f"{key}={item}" for key, item in value.items()) or "-"
    if isinstance(value, (list, tuple)):
        if not value:
            return "(none)"
        # Flatten nested records: MX and SOA are dicts inside a list, and
        # "{'preference': 10}" in a terminal reads as noise.
        shown = ", ".join(_console_value(item) for item in value[:8])
        return shown if len(value) <= 8 else f"{shown} (+{len(value) - 8} more)"
    if value is None or value == "":
        return "-"
    return str(value)


def _console_plain(report: dict[str, Any]) -> str:
    """Render the summary without ``rich``."""
    summary = report.get("summary", {}) or {}
    lines = [
        f"ReconX {report['version']} - {report['target']}",
        f"Generated {report['generated_at']} in {report['duration_seconds']}s",
    ]

    for name in report["modules"]:
        data = report["results"][name]
        lines.append("")
        if "error" in data:
            lines.append(f"[{name}] failed: {data['error']}")
            continue

        lines.append(f"[{name}]")
        section = _section_body(name, data)
        for label, value in section["rows"]:
            lines.append(f"  {label}: {_console_value(value)}")
        for label, values in section.get("lists", {}).items():
            if values:
                lines.append(f"  {label}: {_console_value(values)}")
        missing = section.get("missing") or []
        if missing:
            lines.append(f"  missing headers: {', '.join(missing)}")
        for warning in data.get("warnings", []) or []:
            lines.append(f"  ! {warning}")

    failed = summary.get("modules_failed") or []
    lines.append("")
    lines.append(
        f"modules with errors: {', '.join(failed)}"
        if failed
        else f"all {summary.get('modules_run', 0)} module(s) completed"
    )
    lines.append("")
    lines.append(_NOTICE)
    return "\n".join(lines) + "\n"


def render(report: dict[str, Any], fmt: str) -> str:
    """Render ``report`` in the requested format.

    Args:
        report: A report dict from :func:`reconx.core.run`.
        fmt: One of :data:`FORMATS`.

    Returns:
        The rendered report.

    Raises:
        ValueError: If ``fmt`` is not a supported format.
    """
    if fmt == "json":
        return to_json(report)
    if fmt == "md":
        return markdown(report)
    if fmt == "html":
        return to_html(report)
    if fmt == "text":
        return console(report)
    raise ValueError(f"unknown format {fmt!r}; expected one of {', '.join(FORMATS)}")
