"""Conversion report: the transparency layer.

FortiConverter buries warnings as comments inside config-all.txt. Here the
report is a first-class artifact (markdown + JSON): per-entity counts, a
conversion-coverage estimate, every finding with severity and source
file:line provenance, and every unconverted source line grouped by kind.
The contract: nothing is dropped silently.
"""
from __future__ import annotations

import html as _html
import json
from dataclasses import dataclass, field

from .model import FirewallConfig, SourceRef


@dataclass
class Finding:
    level: str  # info | warn | error
    area: str
    message: str
    loc: str = ""


@dataclass
class Report:
    findings: list[Finding] = field(default_factory=list)
    meta: dict = field(default_factory=dict)

    def add(self, level: str, area: str, message: str,
            ref: SourceRef | None = None):
        self.findings.append(
            Finding(level, area, message, ref.loc() if ref else "")
        )

    def absorb_parser_findings(self, cfg: FirewallConfig):
        for level, area, msg, ref in cfg.meta.get("findings", []):
            self.add(level, area, msg, ref)

    def count(self, level: str) -> int:
        return sum(1 for f in self.findings if f.level == level)

    # -- rendering -----------------------------------------------------------

    def to_json(self, cfg: FirewallConfig | None = None) -> str:
        payload = {
            "meta": self.meta,
            "summary": self.summary_counts(cfg),
            "findings": [vars(f) for f in self.findings],
            "unparsed": [
                {"loc": r.loc(), "line": r.raw}
                for r in (cfg.unparsed if cfg else [])
            ],
        }
        return json.dumps(payload, indent=2)

    def summary_counts(self, cfg: FirewallConfig | None) -> dict:
        out = {
            "errors": self.count("error"),
            "warnings": self.count("warn"),
            "infos": self.count("info"),
        }
        if cfg:
            out.update({
                "interfaces": len(cfg.interfaces),
                "addresses": len(cfg.addresses),
                "address_groups": len(cfg.addr_groups),
                "services": len(cfg.services),
                "service_groups": len(cfg.svc_groups),
                "policies": len(cfg.policies),
                "vips": len(cfg.vips),
                "nat_intents": len(cfg.nats),
                "routes": len(cfg.routes),
                "unparsed_lines": len(cfg.unparsed),
            })
        return out

    def coverage(self, cfg: FirewallConfig, source_text: str) -> float:
        meaningful = sum(
            1 for ln in source_text.splitlines()
            if ln.strip() and not ln.strip().startswith(("!", ":"))
        )
        if not meaningful:
            return 1.0
        return max(0.0, 1.0 - len(cfg.unparsed) / meaningful)

    def to_markdown(self, cfg: FirewallConfig | None = None,
                    source_text: str = "") -> str:
        lines: list[str] = ["# fwforge conversion report", ""]
        for k, v in self.meta.items():
            lines.append(f"- **{k}**: {v}")
        if cfg and source_text:
            pct = self.coverage(cfg, source_text) * 100
            lines.append(f"- **source lines converted or accounted for**: "
                         f"{pct:.1f}%")
        lines.append("")

        counts = self.summary_counts(cfg)
        lines += ["## Summary", "", "| item | count |", "|---|---|"]
        for k, v in counts.items():
            lines.append(f"| {k} | {v} |")
        lines.append("")

        for level, title in (("error", "Errors — must fix"),
                             ("warn", "Warnings — review"),
                             ("info", "Notes")):
            items = [f for f in self.findings if f.level == level]
            if not items:
                continue
            lines += [f"## {title} ({len(items)})", ""]
            for f in items:
                loc = f" `[{f.loc}]`" if f.loc else ""
                lines.append(f"- **{f.area}**: {f.message}{loc}")
            lines.append("")

        if cfg and cfg.unparsed:
            lines += [f"## Unconverted source lines ({len(cfg.unparsed)})", "",
                      "Grouped by leading keyword; every line is listed in "
                      "the JSON report.", ""]
            groups: dict[str, list[SourceRef]] = {}
            for r in cfg.unparsed:
                key = (r.raw.split() or ["?"])[0]
                groups.setdefault(key, []).append(r)
            for key in sorted(groups, key=lambda k: -len(groups[k])):
                refs = groups[key]
                lines.append(f"- `{key}` × {len(refs)}")
                for r in refs[:3]:
                    lines.append(f"    - `{r.raw[:100]}` [{r.loc()}]")
                if len(refs) > 3:
                    lines.append(f"    - … {len(refs) - 3} more")
            lines.append("")
        return "\n".join(lines) + "\n"

    def to_html(self, cfg: FirewallConfig | None = None,
                source_text: str = "") -> str:
        """Self-contained, print-friendly audit/documentation report."""
        e = _html.escape
        title = e(str(self.meta.get("source", "conversion")))

        def meta_rows() -> str:
            rows = "".join(
                f"<tr><th>{e(str(k).replace('_', ' '))}</th>"
                f"<td>{e(str(v))}</td></tr>"
                for k, v in self.meta.items())
            if cfg and source_text:
                pct = self.coverage(cfg, source_text) * 100
                rows += ("<tr><th>source lines converted or accounted "
                         f"for</th><td>{pct:.1f}%</td></tr>")
            return rows

        counts = self.summary_counts(cfg)
        count_rows = "".join(
            f"<tr><th>{e(str(k).replace('_', ' '))}</th><td>{v}</td></tr>"
            for k, v in counts.items())

        sections = []
        for level, label in (("error", "Errors — must fix"),
                             ("warn", "Warnings — review"),
                             ("info", "Notes")):
            items = [f for f in self.findings if f.level == level]
            if not items:
                continue
            lis = "".join(
                f'<li class="{level}"><b>{e(f.area)}</b> {e(f.message)}'
                + (f' <span class="loc">[{e(f.loc)}]</span>' if f.loc
                   else "") + "</li>"
                for f in items)
            sections.append(
                f"<h2>{label} ({len(items)})</h2><ul>{lis}</ul>")

        unparsed = ""
        if cfg and cfg.unparsed:
            rows = "".join(
                f"<tr><td><code>{e(r.raw[:120])}</code></td>"
                f"<td>{e(r.loc())}</td></tr>"
                for r in cfg.unparsed[:100])
            more = (f"<p class='mut'>… {len(cfg.unparsed) - 100} more in "
                    "the JSON report</p>" if len(cfg.unparsed) > 100 else "")
            unparsed = (f"<h2>Unconverted source lines "
                        f"({len(cfg.unparsed)})</h2>"
                        f"<table>{rows}</table>{more}")

        return f"""<!doctype html><html><head><meta charset="utf-8">
<title>fwforge report — {title}</title><style>
body{{font:13px/1.5 -apple-system,"Segoe UI",Roboto,Arial,sans-serif;
 color:#2b3440;max-width:880px;margin:2rem auto;padding:0 1.2rem}}
h1{{font-size:1.3rem;border-bottom:3px solid #266798;
 padding-bottom:.4rem}}
h2{{font-size:1rem;margin:1.4rem 0 .5rem}}
table{{border-collapse:collapse;width:100%;font-size:.88rem;
 margin:.4rem 0 1rem}}
th,td{{text-align:left;padding:.3rem .55rem;
 border-bottom:1px solid #dbe1e8;vertical-align:top}}
th{{color:#69768a;font-weight:600;width:16rem}}
ul{{list-style:none;padding:0}}
li{{padding:.4rem .6rem;border-radius:6px;margin-bottom:.3rem;
 font-size:.88rem}}
li.error{{background:#fdecea}}li.warn{{background:#fff4e5}}
li.info{{background:#f0f3f7}}
.loc,.mut{{color:#69768a;font-size:.8rem}}
code{{font-size:.82rem}}
@media print{{body{{margin:0;max-width:none}}
 li{{break-inside:avoid}}}}
</style></head><body>
<h1>fwforge conversion report</h1>
<table>{meta_rows()}</table>
<h2>Summary</h2>
<table>{count_rows}</table>
{''.join(sections)}
{unparsed}
<p class="mut">Generated by {_html.escape(str(self.meta.get('tool',
'fwforge')))} — print this page to PDF for a shareable audit document.</p>
</body></html>
"""
