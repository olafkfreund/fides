# Fides — task runner.  `just` with no args lists everything.

default:
    @just --list

# ---------- demo ----------

# Live demo — `just demo` full, `just demo dry` walkthrough, `just demo readonly` safe.
demo mode="full": build
    @PATH="{{justfile_directory()}}/bin:$PATH" demo/demo.sh {{mode}}

# Print the workflow without contacting a server or writing anything.
demo-dry:
    @demo/demo.sh dry

# Read-only tour — safe to run against production.
demo-readonly: build
    @PATH="{{justfile_directory()}}/bin:$PATH" demo/demo.sh readonly

# Unattended run: no Enter prompts, no pauses (CI / recording).
demo-fast: build
    @PATH="{{justfile_directory()}}/bin:$PATH" DEMO_NO_PAUSE=1 DEMO_PACE=0 demo/demo.sh full

# The Fides <-> ServiceNow bidirectional proof. Creates a real change request.
demo-servicenow:
    @scripts/servicenow-demo.sh

# Render every VHS screencast to demo/screencasts/out/*.gif (git-ignored).
demo-render: build
    #!/usr/bin/env bash
    set -euo pipefail
    cd demo/screencasts && mkdir -p out
    for t in *.tape; do
      echo "==> $t"
      PATH="{{justfile_directory()}}/bin:$PATH" nix run nixpkgs#vhs -- "$t"
    done

# ---------- build & checks ----------

# Build the fides CLI into ./bin (what the demo recipes put on PATH).
build:
    @go build -o bin/fides ./cmd/cli

# The pre-merge gate: build, vet, test.
check:
    go build ./...
    go vet ./...
    go test ./...

# ---------- markdown ----------

# Lint markdown you've changed vs main — quick local pass while writing.
lint-md:
    #!/usr/bin/env bash
    set -euo pipefail
    files=$(git diff --name-only --diff-filter=d origin/main...HEAD -- '*.md' 2>/dev/null \
            || git diff --name-only --diff-filter=d main -- '*.md')
    # Include not-yet-committed work so you catch it before pushing.
    files="$files $(git diff --name-only --diff-filter=d -- '*.md'; git ls-files -o --exclude-standard -- '*.md')"
    files=$(echo $files | tr ' ' '\n' | sort -u | grep -v '^$' || true)
    if [ -z "$files" ]; then echo "no changed markdown"; exit 0; fi
    echo "$files" | sed 's/^/  /'
    echo "$files" | tr '\n' '\0' | xargs -0 -r markdownlint

# Lint every tracked markdown file — this is what CI enforces.
lint-md-all:
    @git ls-files '*.md' -z | xargs -0 -r markdownlint

# Do docs/*.md and their web/*.md twins document the same sections?
# Not a byte diff: the two copies legitimately differ in front matter and links.
check-docs-parity:
    @scripts/check-docs-web-parity.sh

# Auto-fix what markdownlint can fix, repo-wide. Review the diff before committing.
lint-md-fix:
    @git ls-files '*.md' -z | xargs -0 -r markdownlint --fix
    @echo "fixed what could be fixed — run 'just lint-md-all' for the remainder"
