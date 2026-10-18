#!/usr/bin/env bash
# No long dashes in any tracked file (CLAUDE.md invariant 11): not in code,
# comments, docs, JSON or workflow files.
#
# WHY IT IS PYTHON AND NOT GREP
#
# The obvious `grep -P '\x{2014}'` is a trap the estate has already been caught
# by: some grep builds accept the pattern, match nothing, exit 1, and read as a
# clean run. A check that cannot fail is worse than no check, so this one
# decodes the bytes itself and counts. Run it with --prove and it plants a long
# dash in a temporary tracked-looking file and requires itself to find it.
set -uo pipefail
cd "$(git rev-parse --show-toplevel)" || exit 1

python3 - "${1:-}" <<'PY'
import pathlib, subprocess, sys, tempfile

# Built from its codepoint rather than typed, so this file is not itself the
# one hit every run reports.
EM = chr(0x2014)


def scan(paths):
    hits = []
    for p in paths:
        try:
            text = pathlib.Path(p).read_text(encoding="utf-8")
        except (UnicodeDecodeError, OSError):
            continue
        for n, line in enumerate(text.splitlines(), 1):
            if EM in line:
                hits.append((p, n, line.strip()[:90]))
    return hits


tracked = [p for p in subprocess.run(["git", "ls-files", "-z"], capture_output=True, check=True)
           .stdout.decode("utf-8", "replace").split("\0") if p]
if not tracked:
    print("FAIL: git tracks no file here, so this check measured nothing.")
    sys.exit(1)

if sys.argv[1:] == ["--prove"]:
    with tempfile.TemporaryDirectory() as d:
        probe = pathlib.Path(d) / "probe.txt"
        probe.write_text(f"one long dash {EM} here\n", encoding="utf-8")
        if not scan([str(probe)]):
            print("FAIL: this script could not find a long dash it planted itself,")
            print("      so a clean report from it means nothing.")
            sys.exit(1)
    print("OK: the planted long dash was found, so a clean report means something.")

hits = scan(tracked)
for path, n, line in hits:
    print(f"FAIL: {path}:{n} carries a long dash: {line}")
if hits:
    print("\nUse a comma, a colon, parentheses, or a short hyphen.")
    sys.exit(1)
print(f"OK: no long dash in any of the {len(tracked)} tracked files.")
PY
