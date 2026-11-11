#!/usr/bin/env python3
"""Every `uses:` in .github/workflows must reference a full 40-character commit SHA.

A tag like @v4 is a pointer the action's owner (or whoever compromises them) can move
to different code at any time; a commit SHA can't move. Keep the version as a trailing
comment so humans and Dependabot can read it:

    uses: actions/checkout@11bd71901bbe5b1630ceea73d27597364c9af683  # v4.2.2

Resolve a tag to its commit with:
    gh api repos/OWNER/REPO/commits/TAG --jq .sha

Usage: py scripts/check_pinned_actions.py [--warn]   (python3 on macOS/Linux)   (--warn: report, exit 0)
"""
import pathlib, re, sys

warn_only = "--warn" in sys.argv
level = "warning" if warn_only else "error"
bad = []
for wf in sorted(pathlib.Path(".github/workflows").glob("*.y*ml")):
    for n, line in enumerate(wf.read_text(encoding="utf-8").splitlines(), 1):
        m = re.match(r"\s*(?:-\s*)?uses:\s*['\"]?([^\s'\"#]+)", line)
        if not m:
            continue
        ref = m.group(1)
        if ref.startswith("./"):
            continue  # local action, versioned with this repo
        if ref.startswith("docker://"):
            ok = "@sha256:" in ref
        else:
            ok = re.search(r"@[0-9a-f]{40}$", ref) is not None
        if not ok:
            bad.append((wf, n, ref))

for wf, n, ref in bad:
    repo, _, tag = ref.partition("@")
    print(f"::{level} file={wf},line={n}::{ref} is not pinned to a commit SHA. "
          f"Run: gh api repos/{'/'.join(repo.split('/')[:2])}/commits/{tag or 'TAG'} --jq .sha")
print(f"{len(bad)} unpinned action reference(s)" if bad else "all actions pinned to commit SHAs")
sys.exit(1 if bad and not warn_only else 0)
