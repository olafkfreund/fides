#!/usr/bin/env bash
# Do docs/*.md and their web/*.md twins document the same things?
#
# NOT a byte comparison, and it must never become one: the two copies are
# legitimately different files. docs/ carries Jekyll front matter that would
# render as junk in the portal, links to GitHub Pages URLs (/docs/guide.html),
# and links into docs/servicenow/ -- a subdirectory web/ does not have. web/ is
# a flat subset of the doc set, so it links sideways and, where a doc is
# missing entirely, reasonably reworded around it.
#
# What actually goes wrong is a feature getting documented in one copy and not
# the other: on 2026-08-20 web/mcp-server.md was missing the whole in-browser
# WebMCP section (the portal's own assistant, undocumented in the portal),
# web/features.md had no Cosign/Sigstore section, and docs/features.md did not
# mention the OTLP SIEM sink -- all three shipped features.
#
# Section headings are the cheapest signal for that, and they tolerate the
# rewording and condensing the two copies are entitled to.
#
#   scripts/check-docs-web-parity.sh            # report drift, exit 1 if any
set -uo pipefail
cd "$(dirname "$0")/.." || { echo "cannot reach the repo root" >&2; exit 2; }

rc=0
for w in web/*.md; do
  b=$(basename "$w")
  # web/README.md is the portal's own landing page, not a twin of the repo README.
  [ "$b" = "README.md" ] && continue
  [ -f "docs/$b" ] || continue

  # Compare heading TEXT only: strip the leading #s, any "N." numbering, inline
  # code/emphasis marks, and trailing punctuation.
  norm() {
    grep -E '^#{2,3} ' "$1" \
      | sed -E 's/^#+ +//; s/^[0-9]+\. *//; s/[`*_]//g; s/[[:space:]]+$//' \
      | sort
  }

  if ! d=$(diff <(norm "docs/$b") <(norm "$w")); then
    echo "drift: $b"
    echo "$d" | sed -E 's/^</  only in docs\/: /; s/^>/  only in web\/ : /' | grep -E 'only in'
    rc=1
  fi
done

if [ $rc -eq 0 ]; then
  echo "docs/ and web/ document the same sections."
else
  echo
  echo "A section exists in one copy and not the other. Either port it across, or"
  echo "-- if the section is genuinely inapplicable to that copy -- say so here."
fi
exit $rc
