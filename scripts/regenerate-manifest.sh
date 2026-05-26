#!/usr/bin/env bash
# Regenerate CORPUS-MANIFEST.md from the actual file contents.
#
# Usage:  ./scripts/regenerate-manifest.sh
#
# Run this whenever ANY markdown file in the repo is added, edited, or removed.
# A CI workflow should also run this and fail the build if the working tree
# is dirty after — that catches drift between the manifest and reality.

set -euo pipefail

# cd to repo root regardless of where the script is invoked from
cd "$(dirname "$0")/.."

python3 - <<'PYEOF'
import hashlib, os, re

files = []
for root, dirs, fnames in os.walk('.'):
    dirs[:] = [d for d in dirs if d != '.git']
    for fn in fnames:
        if fn.endswith('.md'):
            files.append(os.path.join(root, fn))
files.sort()

def extract_id_title(path):
    if 'known-vectors/' not in path or 'INDEX' in path:
        return ('', '')
    try:
        with open(path) as f:
            content = f.read()
        m = re.match(r'^---\n(.*?)\n---', content, re.DOTALL)
        if not m:
            return ('', '')
        fm = m.group(1)
        id_match = re.search(r'^id:\s*(\d+)', fm, re.MULTILINE)
        title_match = re.search(r'^title:\s*"?([^"\n]+)"?', fm, re.MULTILINE)
        id_val = id_match.group(1) if id_match else ''
        title_val = title_match.group(1).rstrip('"') if title_match else ''
        return (id_val, title_val)
    except Exception:
        return ('', '')

header = """# AUDITOR Corpus Manifest

Generated from full recursive read of all markdown files in this folder.

To regenerate after any edit:
```bash
./scripts/regenerate-manifest.sh
```

The self-row for `./CORPUS-MANIFEST.md` cannot be verified by recomputing its
own hash (circular). For external integrity verification, rely on signed git
tags (`git tag -v <tag>`) rather than this manifest alone.

| File | Lines | SHA256 | ID | Title |
|---|---:|---|---:|---|
"""

SELF_REF_PLACEHOLDER = '0' * 64  # the manifest cannot hash itself; see header note

rows = []
for path in files:
    with open(path, 'rb') as f:
        data = f.read()
    lines = data.count(b'\n')
    if not data.endswith(b'\n') and data:
        lines += 1
    if path == './CORPUS-MANIFEST.md':
        h = SELF_REF_PLACEHOLDER
    else:
        h = hashlib.sha256(data).hexdigest()
    id_col, title_col = extract_id_title(path)
    rows.append(f"| {path} | {lines} | {h} | {id_col} | {title_col} |")

with open('CORPUS-MANIFEST.md', 'w') as f:
    f.write(header + '\n'.join(rows) + '\n')

print(f"Wrote CORPUS-MANIFEST.md with {len(rows)} rows.")
PYEOF
