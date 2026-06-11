"""Output packaging, in two shapes by conversion type:

- FortiGate -> FortiGate migration produces a COMPLETE, restorable config,
  so it ships as one full `<stem>.conf` file you restore wholesale
  (write_full). Splitting a backup would be wrong — you restore it as a
  unit.
- Everything else -> FortiGate (ASA, Palo Alto) produces a partial paste-
  script, so it ships FortiConverter-style: `<stem>.config-all.txt` plus
  one `.txt` per config branch for selective CLI application (write_split).

Both embed the findings as `#` comments (errors/warnings only) inserted
AFTER any leading header, so a restorable config keeps `#config-version=`
on line 1; FortiOS ignores `#` lines on load, so output stays paste- and
restore-safe. The richer md/JSON reports remain separate artifacts.
"""
from __future__ import annotations

import re
from pathlib import Path

from ..report import Report


def _fname(name: str) -> str:
    return re.sub(r"[^a-z0-9]+", "-", name.lower()).strip("-") or "section"


def split_branches(text: str) -> list[tuple[str, str]]:
    """Split FortiOS CLI text into top-level `config <x> ... end` blocks.
    Returns [(branch-name, block-text)]; lines outside any block (the
    header) are not returned — they live only in config-all. A
    `config vdom` block splits into per-VDOM sections, each re-wrapped
    so every branch file pastes standalone."""
    lines = text.splitlines()
    out: list[tuple[str, str]] = []
    depth = 0
    start = None
    name = None
    for idx, raw in enumerate(lines):
        s = raw.strip()
        if s.startswith("config "):
            if depth == 0:
                start = idx
                name = s[len("config "):].strip()
            depth += 1
        elif s == "end" and depth > 0:
            depth -= 1
            if depth == 0 and start is not None:
                out.append((name or "section",
                            "\n".join(lines[start:idx + 1])))
                start = None
    final: list[tuple[str, str]] = []
    for nm, block in out:
        if nm == "vdom":
            final += _split_vdom_block(block)
        else:
            final.append((nm, block))
    return final


def _split_vdom_block(block: str) -> list[tuple[str, str]]:
    lines = block.splitlines()
    if len(lines) < 3 or not lines[1].strip().startswith("edit "):
        return [("vdom", block)]
    vdom = lines[1].strip()[5:].strip().strip('"')
    inner = "\n".join(lines[2:-1])
    subs = split_branches(inner)
    if not subs:
        # the VDOM-creation block (edit/next pairs, no sections)
        return [("vdom", block)]
    return [(f"{vdom} {nm}",
             f"config vdom\nedit {vdom}\n{sub}\nend")
            for nm, sub in subs]


# finding messages use a few typographic characters; fold them to ASCII —
# these comments land inside emitted CLI files, which must paste safely
# into any console
_ASCII_FOLD = str.maketrans({
    "—": "-", "–": "-", "…": "...",
    "‘": "'", "’": "'", "“": '"', "”": '"',
    "→": "->", "×": "x",
})


def _ascii(text: str) -> str:
    return text.translate(_ASCII_FOLD).encode(
        "ascii", "replace").decode("ascii")


def _finding_comments(report: Report, stem: str) -> list[str]:
    errs, warns = report.count("error"), report.count("warn")
    block = [
        "#",
        f"# fwforge conversion of {stem}: {errs} error(s), {warns} "
        "warning(s)",
        f"# full report: {stem}.report.md / {stem}.report.json",
        "# (these '#' lines are comments and are ignored on load)",
    ]
    if errs:
        block.append("# ERRORS must be resolved before this config is "
                     "production-ready.")
    for f in report.findings:
        if f.level not in ("error", "warn"):
            continue
        tag = "ERROR" if f.level == "error" else "WARN"
        loc = f" [{f.loc}]" if f.loc else ""
        msg = _ascii(f.message.replace("\n", " "))
        block.append(f"# [{tag}] {f.area}: {msg}{loc}")
    block.append("#")
    block.append("")
    return block


def _with_comments(full_text: str, comments: list[str]) -> str:
    lines = full_text.split("\n")
    i = 0
    while i < len(lines) and lines[i].startswith("#"):
        i += 1  # keep the leading #config-version header block on top
    return "\n".join(lines[:i] + comments + lines[i:])


def write_full(outdir: Path, stem: str, full_text: str,
               report: Report) -> dict:
    """FortiGate->FortiGate: one restorable <stem>.conf file."""
    path = outdir / f"{stem}.conf"
    path.write_text(
        _with_comments(full_text, _finding_comments(report, stem)),
        encoding="utf-8")
    return {"main": path, "main_name": path.name, "split": False,
            "branch_count": 0}


def write_split(outdir: Path, stem: str, full_text: str,
                report: Report) -> dict:
    """Cross-vendor: <stem>.config-all.txt + <stem>.branches/<NN>-x.txt."""
    config_all = outdir / f"{stem}.config-all.txt"
    config_all.write_text(
        _with_comments(full_text, _finding_comments(report, stem)),
        encoding="utf-8")

    branch_dir = outdir / f"{stem}.branches"
    branch_dir.mkdir(parents=True, exist_ok=True)
    for old in branch_dir.glob("*.txt"):  # clear stale branches on re-run
        old.unlink()

    branches = split_branches(full_text)
    width = max(2, len(str(len(branches))))
    seen: dict[str, int] = {}
    paths: list[Path] = []
    for n, (name, block) in enumerate(branches, start=1):
        fn = _fname(name)
        if fn in seen:
            seen[fn] += 1
            fn = f"{fn}-{seen[fn]}"
        else:
            seen[fn] = 1
        p = branch_dir / f"{str(n).zfill(width)}-{fn}.txt"
        p.write_text(block + "\n", encoding="utf-8")
        paths.append(p)

    return {"main": config_all, "main_name": config_all.name, "split": True,
            "config_all": config_all, "branch_dir": branch_dir,
            "branches": paths, "branch_count": len(paths)}
