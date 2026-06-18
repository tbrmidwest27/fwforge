"""AI Advisor — Claude Code subprocess integration for the fwforge GUI.

Routes through the locally-authenticated `claude` CLI so no separate API key
is needed; uses the user's Claude.ai plan. Requires Claude Code installed and
authenticated on this machine.
"""
from __future__ import annotations

import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

_USER_FILE = Path("~/.fwforge/pan_apps.json").expanduser()

# The advisor must be a single-shot text generator, NOT an agent. Launched from
# the Flask process's cwd (the fwforge repo), `claude -p` otherwise boots full
# Claude Code: it loads the project CLAUDE.md / .claude agents / memory, reads
# git status, and "helpfully" tries to review the repo instead of summarizing
# the data we hand it. This system prompt strips the agent identity; we also
# run it in a neutral cwd and load only user settings (see _run_claude).
_ADVISOR_SYSTEM = (
    "You are a single-shot technical writing assistant for a firewall "
    "configuration converter. Produce ONLY the text the user's message asks "
    "for, derived solely from the information given in that message. Do not "
    "use any tools, do not read or reference any files, repository, git "
    "state, or codebase, and do not ask clarifying questions — answer "
    "directly."
)

_FORTIGUARD_CATS = (
    "P2P, VoIP, Video/Audio, Proxy, Remote.Access, Game, General.Interest, "
    "Network.Service, Update, Email, Storage.Backup, Social.Media, Web.Client, "
    "Collaboration, Business, Cloud.IT"
)


def _run_claude(prompt: str, timeout: int = 90) -> str:
    """Invoke `claude -p` with the prompt on stdin and return stdout.

    The prompt is handed over as a real FILE on stdin, not as an argv
    argument and not via a pipe:
      * argv overflows cmd.exe's ~8191-char command-line limit on big
        prompts (the App-ID gap analyzer) -> "The command line is too long";
      * a PIPE forwarded through the Windows .cmd shim is racy — claude
        gives up after ~3s ("no stdin data received") if cmd.exe hasn't
        forwarded the pipe to node yet.
    A file handle is inherited reliably (like `claude < file`) and has no
    size limit. Raises RuntimeError on failure.
    """
    exe = shutil.which("claude") or "claude"
    tf = tempfile.NamedTemporaryFile(
        "w", suffix=".txt", delete=False, encoding="utf-8")
    try:
        tf.write(prompt)
        tf.close()
        with open(tf.name, "r", encoding="utf-8") as fin:
            result = subprocess.run(
                [exe, "-p", "--output-format", "text",
                 # replace the agentic system prompt so it can't act as a
                 # repo reviewer; drop the dynamic cwd/memory/git sections
                 "--system-prompt", _ADVISOR_SYSTEM,
                 "--exclude-dynamic-system-prompt-sections",
                 # load only user-level settings, never this project's
                 # .claude agents/settings
                 "--setting-sources", "user"],
                stdin=fin,
                capture_output=True,
                text=True,
                timeout=timeout,
                # neutral cwd: don't inherit the fwforge repo, so no project
                # CLAUDE.md / memory / git context leaks into the response
                cwd=tempfile.gettempdir(),
                # shell=True so cmd.exe handles the .cmd wrapper on Windows
                shell=(sys.platform == "win32"),
            )
    except subprocess.TimeoutExpired:
        raise RuntimeError("Claude timed out — try again")
    except FileNotFoundError:
        raise RuntimeError(
            "claude CLI not found — install Claude Code and sign in first"
        )
    finally:
        try:
            os.unlink(tf.name)
        except OSError:
            pass
    if result.returncode != 0:
        msg = (result.stderr or "").strip()
        raise RuntimeError(msg or f"claude exited {result.returncode}")
    return result.stdout.strip()


def conversion_summary(vendor: str, target: str, r: dict) -> str:
    """Generate a plain-English paragraph summary of the conversion result."""
    counts = r.get("counts", {})
    meta_rows = "\n".join(
        f"  {k.replace('_', ' ')}: {v}"
        for k, v in (r.get("meta") or {}).items()
        if isinstance(v, (str, int, float))
    )
    top: list[str] = []
    for level in ("error", "warn"):
        for f in (r.get("findings", {}).get(level) or [])[:8]:
            top.append(f"[{level.upper()}] {f['area']}: {f['message']}")

    prompt = (
        f"You are a firewall migration expert reviewing a fwforge conversion.\n\n"
        f"Source vendor: {vendor}\n"
        f"Target: FortiOS {target}\n"
        f"Mode: {r.get('mode', 'cross')}\n"
        f"Result: {counts.get('errors', 0)} errors, "
        f"{counts.get('warnings', 0)} warnings, {counts.get('notes', 0)} notes\n"
        f"Output: {r.get('out_size', 0)} lines\n\n"
        f"Conversion metadata:\n{meta_rows or '  (none)'}\n\n"
        f"Top findings:\n"
        + ("\n".join(top) if top else "  (none)")
        + "\n\nWrite a 2-3 paragraph plain-English summary a network engineer "
        "can paste into a migration handoff document. Cover: (1) what converted "
        "successfully, (2) what was flagged and why, (3) what needs manual "
        "attention before the config is loaded on a FortiGate. Be specific and "
        "technical. Write in prose, not bullet points."
    )
    return _run_claude(prompt, timeout=90)


def explain_finding(area: str, message: str, vendor: str, target: str) -> str:
    """Return a plain-English explanation of a single conversion finding."""
    prompt = (
        f"You are a FortiOS and {vendor} firewall expert.\n\n"
        f"A fwforge conversion ({vendor} to FortiOS {target}) produced this finding:\n"
        f"  Area:    {area}\n"
        f"  Message: {message}\n\n"
        "Explain this to a network engineer in plain English:\n"
        "1. What does this mean in concrete terms?\n"
        "2. Why did it happen?\n"
        "3. What should they do about it?\n\n"
        "Keep it to 3-5 sentences. Be specific and actionable. "
        "Do not repeat the finding verbatim."
    )
    return _run_claude(prompt, timeout=45)


def research_app_gaps(
    all_findings: list[dict], vendor: str
) -> tuple[dict, str]:
    """Identify unmapped PAN App-IDs from conversion findings and research them.

    Filters findings for app-related warnings, passes them to Claude, and
    returns (entries_dict, raw_response). entries_dict is ready to merge into
    pan_apps.json; it may be empty if no app gaps are found or if JSON parsing
    fails (raw_response still contains the full Claude output).
    """
    app_findings = [
        f for f in all_findings
        if (
            "app" in (f.get("area") or "").lower()
            or "service all" in (f.get("message") or "").lower()
            or "unmapped" in (f.get("message") or "").lower()
            or "application" in (f.get("message") or "").lower()
        )
    ]
    if not app_findings:
        return {}, ""

    findings_text = "\n".join(
        f"  [{f['area']}] {f['message']}" for f in app_findings[:60]
    )

    prompt = (
        f"You are filling a PAN App-ID database for the fwforge firewall converter.\n\n"
        f"Below are conversion findings from a {vendor} config. Some warn about "
        "App-IDs that are unknown, causing overly-permissive 'service ALL' "
        "fallbacks in the FortiOS output.\n\n"
        f"Conversion findings:\n{findings_text}\n\n"
        "Step 1: Identify the PAN App-ID names mentioned in these findings that "
        "lack port/service data and caused 'service ALL' fallbacks.\n\n"
        "Step 2: Research each one using public sources (PAN Applipedia, IANA, "
        "vendor docs).\n\n"
        "Step 3: Return ONLY a valid JSON object (no markdown, no explanation) "
        "with this exact structure:\n\n"
        '{\n'
        '  "apps": {\n'
        '    "app-name": {\n'
        '      "ports": [{"proto": "tcp", "ports": "80"}],\n'
        '      "category": "pan-category",\n'
        '      "subcategory": "pan-subcategory",\n'
        '      "risk": 3,\n'
        '      "transport": false,\n'
        '      "builtin_services": [],\n'
        '      "fortiguard_category": "Web.Client",\n'
        '      "sig_aliases": []\n'
        '    }\n'
        '  }\n'
        '}\n\n'
        f"fortiguard_category must be exactly one of: {_FORTIGUARD_CATS}\n"
        "Use null if none fit. Use [] for ports on dynamic apps (P2P, SIP, RTP). "
        "If no unmapped App-IDs are found, return {\"apps\": {}}. "
        "Return ONLY the JSON object."
    )

    raw = _run_claude(prompt, timeout=120)

    # Strip markdown fences if Claude included them despite instructions
    text = re.sub(r"^```(?:json)?\s*", "", raw.strip(), flags=re.MULTILINE)
    text = re.sub(r"\s*```$", "", text, flags=re.MULTILINE).strip()

    try:
        parsed = json.loads(text)
        entries = {
            k: v
            for k, v in parsed.get("apps", {}).items()
            if not k.startswith("_") and isinstance(v, dict)
        }
        return entries, raw
    except (json.JSONDecodeError, AttributeError, TypeError):
        return {}, raw


def merge_to_user_db(entries: dict) -> tuple[int, str]:
    """Merge app entries into ~/.fwforge/pan_apps.json (the user override file).

    The user file takes precedence over the bundled baseline at load time, so
    AI-generated entries (which should be human-reviewed) stay out of the repo.
    Returns (count_merged, path_written).
    """
    if not entries:
        return 0, ""

    existing: dict = {}
    if _USER_FILE.exists():
        try:
            existing = json.loads(_USER_FILE.read_text(encoding="utf-8"))
        except (json.JSONDecodeError, OSError):
            existing = {}

    apps = existing.get("apps", {})
    apps.update(entries)
    existing["apps"] = apps
    existing.setdefault("_meta", {}).update(
        {"source": "fwforge ai-advisor", "count": len(apps)}
    )

    _USER_FILE.parent.mkdir(parents=True, exist_ok=True)
    _USER_FILE.write_text(
        json.dumps(existing, indent=2, ensure_ascii=False), encoding="utf-8"
    )
    return len(entries), str(_USER_FILE)
