# Fides Screencasts

Reproducible screencast **sources** for the Fides CLI and portal. The `.tape`
files are [VHS](https://github.com/charmbracelet/vhs) scripts — text, versioned,
and re-rendered whenever the CLI changes. No binary videos are committed; you
render them on demand.

## CLI screencasts (VHS)

| Tape | Shows |
|------|-------|
| `01-quickstart.tape` | The happy path: `trail start → artifact report → attest → verify-chain → change-gate` |
| `02-ci-gate.tape` | The gate commands and the `0/2` exit-code convention CI keys off (GitHub & GitLab) |
| `03-controls-coverage.tape` | Adopt a framework → coverage → enforce → OSCAL export |
| `04-dashboard.tape` | DORA metrics + the live `fides dashboard` TUI |
| `05-supply-chain-runtime.tape` | SBOM/SLSA ingest, `search components`, `impact`/`vex`, `anchor`, snapshots, `env diff`, allow-list |
| `06-advanced-new.tape` | `attest authorship`, feature-flag governance, EU AI Act `model`, `remediation`, OSCAL/CRA reports, ServiceNow grounding |
| `07-live-data.tape` | Read-only live tour: frameworks/coverage, control timeline, flows/trails, evidence search, DORA metrics (safe against a real server) |

### Render

VHS runs the commands in a real shell, so the output is real — point it at a
reachable Fides server with a token and valid IDs.

```bash
# from repo root
export FIDES_SERVER_URL="https://fides.example.com"
export FIDES_API_TOKEN="<service-account-token>"   # never commit this
export ORG_ID="…"  FLOW_ID="…"  ENV_ID="…"  DIGEST="sha256:…"  TRAIL_ID="…"

cd demo/screencasts && mkdir -p out
nix run nixpkgs#vhs -- 01-quickstart.tape          # → out/01-quickstart.gif
# …repeat per tape, or:  for t in *.tape; do nix run nixpkgs#vhs -- "$t"; done
```

`fides` must be on `PATH` (`go build -o fides ./cmd/cli` and add it, or use a
release binary). To also produce an MP4, add `Output out/01-quickstart.mp4`
alongside the `.gif` line in the tape.

The tapes print no secrets — env setup runs inside VHS `Hide` blocks. The IDs
above are the only inputs; supply real ones from your server for real output.

## Portal screencast

The portal tour is a storyboard, not a tape (it's a browser, not a terminal):
see [`portal-storyboard.md`](portal-storyboard.md) for the route-by-route shot
list and narration, and how to capture it with the Chrome automation
`gif_creator` or a screen recorder.

## Output

Rendered `out/` artifacts are git-ignored — regenerate rather than commit them.

## 08-local-gates

`sbom diff` and `vuln diff` — the offline half of Fides. Needs **no server and
no token**, which is also why it is the most reliable tape to re-record.

Its inputs are committed at `fixtures/seed-local-gates.sh` rather than typed
inline: VHS's `Type` takes a quoted string and nested quotes break its parser,
and a screencast whose inputs live in the repo can be re-recorded by anyone.

```bash
cd demo/screencasts
PATH="/path/to/fides-bin:$PATH" nix run nixpkgs#vhs -- 08-local-gates.tape
```
