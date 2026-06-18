"""PostToolUse hook — after a webui template edit: validate Jinja + remind.

Claude Code pipes the tool-call JSON on stdin. For a webui *.html edit we:
  1. Compile the template source with Jinja2 to catch syntax errors
     ({% %} / {{ }}) the moment it's saved — otherwise a broken tag is
     invisible until that exact page is rendered.
  2. Print a reminder that the webui (runs debug=False) must be restarted
     before template changes show up.
Silent + exit 0 for every other edit so it never adds noise. Never blocks.
"""
import json
import sys
from pathlib import Path

try:
    data = json.load(sys.stdin)
except Exception:
    sys.exit(0)

raw = str((data.get("tool_input") or {}).get("file_path", ""))
path = raw.replace("\\", "/")
if not ("/webui/" in path and path.endswith(".html")):
    sys.exit(0)

# 1) Jinja syntax check — report, but never block the edit. parse() validates
#    tag/expression syntax without resolving {% extends %}, which is exactly
#    what we want from a fast save-time check.
try:
    from jinja2 import Environment
    src = Path(raw).read_text(encoding="utf-8")
    Environment().parse(src)
except (ImportError, FileNotFoundError):
    pass
except Exception as e:  # jinja2.TemplateSyntaxError and friends
    line = getattr(e, "lineno", "?")
    print(f"WARNING fwforge: Jinja syntax error in {Path(raw).name} "
          f"(line {line}): {e}")

# 2) restart reminder
print("fwforge: restart the Flask webui (python -m fwforge gui) "
      "to see this template change.")
sys.exit(0)
