# CLAUDE.md

fwforge — open firewall config converter: third-party configs in, clean FortiOS
CLI out. A transparent, clean-room alternative to Fortinet's FortiConverter.

For *what it converts* and *how to run it*, read **README.md**. For history and
the competitive roadmap, read **ROADMAP.md**. This file is only the rules that
aren't obvious from the code.

## Hard constraints
- **Zero runtime dependencies.** Pure Python 3.11+ stdlib only. `flask` (gui)
  and `pytest` (dev) are optional extras in pyproject — never add a runtime dep.
- **Nothing is dropped silently.** Every emitted line traces to a source file +
  line; everything non-convertible goes in the report (`.report.md`/`.json`)
  with its origin. This is the product's core promise — never "handle" an
  unconvertible case by quietly omitting it.
- **No silent rule-broadening.** Reuse a built-in FortiOS service/object only on
  *exact* semantic match (`tcp/443`→`HTTPS` yes; `udp/53`→built-in `DNS` no, it's
  tcp+udp). Non-convertible operators (e.g. `neq`) emit the policy **disabled**
  with a review comment, never a broader rule. This is the bug class the tool exists to prevent.

## Architecture (the pipeline)
`parsers/` (per-vendor: cisco_asa, paloalto, pfsense, juniper_srx, fortios_tree)
→ vendor-neutral IR in `model.py` → `transforms/` → `emit/` (fortios,
fortimanager, package). `pipeline.py` wires it; `cli.py` / `webui/app.py` are
thin frontends over the same pipeline — keep conversion logic out of both.

Two modes: `--mode cross` (foreign → IR → FortiOS, lossy, report accounts for
losses) and `--mode migrate` (FortiOS → FortiOS, lossless structural-tree
re-emit with reference-aware renames).

## Conventions / gotchas
- **FortiOS name-length limits** (interface 15, zone 35, addr/svc 79, policy/UTM
  35, vdom 11) and shared namespaces are enforced centrally in
  `transforms/names.py` + `transforms/limits.py`. Renaming must stay
  reference-aware and namespace-scoped — cross-namespace ref corruption has bitten
  this code before.
- **Web UI runs `debug=False`** — restart `python -m fwforge gui` to see template
  changes. (A PostToolUse hook reminds you + Jinja-syntax-checks on `webui/*.html` saves.)
- Use the project subagents for review before committing: `code-reviewer`,
  `security-auditor`, `conversion-quality`.

## Test / build
```
python -m pip install -e .[dev]
python -m pytest          # testpaths = tests/
```
