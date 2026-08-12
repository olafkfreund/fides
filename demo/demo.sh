#!/usr/bin/env bash
# Fides live demo — record -> verify -> gate -> map to controls.
#
# Runs the narrative end to end against a real server, seeding whatever it
# needs so there is no manual ID harvesting before a demo.
#
#   just demo              full run (seeds a flow/env/trail, then narrates)
#   just demo dry          print the workflow without touching anything
#   just demo readonly     read-only tour, safe against production
#   just demo-servicenow   the ServiceNow bidirectional proof
#
# Env (not needed for `dry`):
#   FIDES_SERVER_URL   required (e.g. https://fides.example.com)
#   FIDES_API_TOKEN    required (org-scoped service-account token)
#   FIDES_FLOW_ID      optional — reuse an existing flow instead of creating one
#   FIDES_ENV_ID       optional — reuse an existing environment
#   DEMO_PACE          seconds to pause between beats (default 2; 0 = no pause)
#   DEMO_NO_PAUSE=1    never wait for Enter (for CI / unattended renders)
set -euo pipefail

MODE="${1:-full}"

# Dry mode is a real execution mode, not a separate description: run() prints
# instead of executing, so the dry walkthrough can never drift from the demo.
DRY=0
if [[ "$MODE" == "dry" ]]; then
  DRY=1
  PACE=0
  DEMO_NO_PAUSE=1
  FIDES_SERVER_URL="${FIDES_SERVER_URL:-https://fides.example.com}"
  FIDES_API_TOKEN="${FIDES_API_TOKEN:-<token>}"
else
  : "${FIDES_SERVER_URL:?set FIDES_SERVER_URL}"
  : "${FIDES_API_TOKEN:?set FIDES_API_TOKEN}"
fi
PACE="${DEMO_PACE:-${PACE:-2}}"

# ---------- presentation helpers ----------
if [[ -t 1 ]]; then
  B=$'\033[1m'; DIM=$'\033[2m'; GOLD=$'\033[33m'; GREEN=$'\033[32m'; RED=$'\033[31m'; R=$'\033[0m'
else
  B=""; DIM=""; GOLD=""; GREEN=""; RED=""; R=""
fi

say()  { printf '\n%s# %s%s\n' "$GOLD" "$*" "$R"; sleep "$PACE"; }
note() { printf '%s  %s%s\n' "$DIM" "$*" "$R"; }

# run: echo the command as the presenter would type it, then actually run it.
# Never let a non-zero exit kill the demo — gates *should* exit 2 sometimes.
run() {
  # Show what a presenter would type: pipelines have to go through `bash -c`,
  # but nobody wants to see the wrapper on a projector.
  # jqf is our jq-or-cat shim; show it as plain `jq` so it doesn't read as a typo.
  if [[ "${1:-}" == "bash" && "${2:-}" == "-c" ]]; then
    printf '%s$ %s%s\n' "$B" "${3//jqf/jq}" "$R"
  else
    printf '%s$ %s%s\n' "$B" "${*//jqf/jq}" "$R"
  fi
  if [[ $DRY -eq 1 ]]; then
    printf '%s  … not executed (dry run)%s\n' "$DIM" "$R"
    return 0
  fi
  local rc=0
  "$@" || rc=$?
  if [[ $rc -eq 0 ]]; then printf '%s  ✓ exit=0%s\n' "$GREEN" "$R"
  else printf '%s  ✗ exit=%d%s\n' "$RED" "$rc" "$R"; fi
  sleep "$PACE"
  return 0
}

beat() {
  [[ "${DEMO_NO_PAUSE:-}" == "1" ]] && return 0
  [[ -t 0 ]] || return 0
  printf '%s  ── Enter to continue ──%s' "$DIM" "$R"; read -r _
}

api() { # api METHOD PATH [JSON]
  curl -fsS -X "$1" -H "Authorization: Bearer $FIDES_API_TOKEN" \
    ${3:+-H 'Content-Type: application/json'} ${3:+-d "$3"} \
    "$FIDES_SERVER_URL$2"
}

# jqf: pretty-filter through jq when it exists, otherwise pass raw JSON through
# so the demo still runs on a machine without jq. Exported — the narrated beats
# pipe through it inside `bash -c` subshells.
jqf() { if command -v jq >/dev/null; then jq "$@"; else cat; fi; }
export -f jqf

if [[ $DRY -eq 0 ]] && ! command -v fides >/dev/null; then
  echo "fides not on PATH — run: just build  (or: go build -o bin/fides ./cmd/cli)" >&2
  exit 1
fi

if [[ $DRY -eq 1 ]]; then
  cat <<EOF

${B}DRY RUN — nothing below is executed, no server is contacted.${R}

  The demo tells one story in five moves:

    ${GOLD}record${R}  a build trail, its artifact, and scanner evidence
    ${GOLD}prove${R}   the evidence chain is untampered  (verify-chain)
    ${GOLD}gate${R}    the release on that evidence      (change-gate, exit 2 = HOLD)
    ${GOLD}map${R}     the evidence onto SOC2 controls   (import + coverage)
    ${GOLD}report${R}  an auditor-ready OSCAL export + DORA metrics

  A real run creates: 1 flow, 1 environment, 1 trail, 1 artifact,
  1 trivy attestation, and imports the SOC2 catalog. All idempotent
  except the trail, which is timestamped and therefore new each run.

  Talking points for each beat: ${B}demo/TALKING-POINTS.md${R}
EOF
fi

# ---------- preflight ----------
say "Preflight: is the server up and is our token good?"
# Deliberately NOT via run() — run() swallows exit codes so gate demos can show
# a red exit=2 without aborting. A bad server/token must stop us here instead of
# failing halfway through in front of an audience.
if [[ $DRY -eq 1 ]]; then
  printf '%s$ fides flow list%s\n%s  … not executed (dry run)%s\n' "$B" "$R" "$DIM" "$R"
elif ! fides flow list >/dev/null 2>&1; then
  printf '%s  ✗ cannot reach %s with this token%s\n' "$RED" "$FIDES_SERVER_URL" "$R" >&2
  printf '    check FIDES_SERVER_URL / FIDES_API_TOKEN, then re-run.\n' >&2
  exit 1
fi
[[ $DRY -eq 0 ]] && printf '%s  ✓ connected%s\n' "$GREEN" "$R"
note "server: $FIDES_SERVER_URL"

# ---------- read-only tour ----------
if [[ "$MODE" == "readonly" ]]; then
  say "Regulated frameworks Fides ships, and how covered we are"
  run bash -c 'fides control frameworks | jqf "map(.framework)"'
  run bash -c 'fides control coverage  | jqf ".controls[:6] | map({framework, control, coverage})"'
  beat

  say "Flows are services; trails are builds of them"
  run bash -c 'fides flow list | jqf "map({name, id})"'
  beat

  say "DORA delivery metrics, derived from the evidence itself"
  run bash -c 'fides metrics | jqf "{trails, attestations, deployments, compliance_rate, change_failure_rate}"'
  say "Read-only tour done — nothing was written."
  exit 0
fi

# ---------- seed ----------
say "Seeding demo objects (idempotent — safe to re-run)"

FLOW_ID="${FIDES_FLOW_ID:-}"
if [[ -z "$FLOW_ID" ]]; then
  printf '%s$ POST /api/v1/flows {"name":"fides-demo"}%s\n' "$B" "$R"
  if [[ $DRY -eq 1 ]]; then
    FLOW_ID="<new-flow-id>"
    printf '%s  … not executed (dry run)%s\n' "$DIM" "$R"
  else
    FLOW_ID=$(api POST /api/v1/flows \
      '{"name":"fides-demo","description":"Created by demo/demo.sh"}' | jqf -r .id)
  fi
fi
note "flow: $FLOW_ID"

ENV_ID="${FIDES_ENV_ID:-}"
if [[ -z "$ENV_ID" ]]; then
  # POST /environments upserts on (org, name), so re-runs reuse the same env.
  printf '%s$ POST /api/v1/environments {"name":"demo-production","type":"k8s"}%s\n' "$B" "$R"
  if [[ $DRY -eq 1 ]]; then
    ENV_ID="<demo-production-id>"
    printf '%s  … not executed (dry run)%s\n' "$DIM" "$R"
  else
    ENV_ID=$(api POST /api/v1/environments \
      '{"name":"demo-production","type":"k8s","description":"Created by demo/demo.sh"}' | jqf -r .id)
  fi
fi
note "env:  $ENV_ID"

# ponytail: fixtures are generated here rather than committed — one less
# directory to keep in sync with whatever the scanners emit this year.
FIX=$(mktemp -d); trap 'rm -rf "$FIX"' EXIT
cat >"$FIX/trivy.json" <<'JSON'
{"SchemaVersion":2,"ArtifactName":"auth-service:1.4.0","Results":[
 {"Target":"auth-service","Class":"os-pkgs","Vulnerabilities":[
  {"VulnerabilityID":"CVE-2024-0001","PkgName":"openssl","Severity":"MEDIUM",
   "Title":"demo finding","InstalledVersion":"3.0.1","FixedVersion":"3.0.2"}]}]}
JSON
DIGEST="sha256:$(printf 'fides-demo-%s' "$FLOW_ID" | sha256sum | cut -d' ' -f1)"

# ---------- 1. record ----------
say "1. Open a build trail — the spine every piece of evidence hangs off"
printf '%s$ fides trail start --flow %s --trail demo-<ts> --commit <sha> --committer <you> --quiet%s\n' \
  "$B" "$FLOW_ID" "$R"
if [[ $DRY -eq 1 ]]; then
  TRAIL_ID="<new-trail-id>"
  printf '%s  … not executed (dry run)%s\n' "$DIM" "$R"
else
  TRAIL_ID=$(fides trail start --flow "$FLOW_ID" --trail "demo-$(date +%s)" \
    --commit "$(git rev-parse HEAD 2>/dev/null || echo demo)" \
    --committer "${USER:-demo}@example.com" --quiet)
fi
note "trail: $TRAIL_ID"
sleep "$PACE"
beat

say "2. Register the artifact the build produced — SHA256 is its fingerprint"
run fides artifact report --trail "$TRAIL_ID" --sha256 "$DIGEST" \
  --name auth-service --type docker
beat

say "3. Attach evidence from a scanner you already run"
run fides attest trivy --trail "$TRAIL_ID" --file "$FIX/trivy.json"
beat

# ---------- 2. prove ----------
say "4. Prove the whole chain is untampered — exit 2 if anyone edited history"
run fides verify-chain --trail "$TRAIL_ID"
beat

# ---------- 3. gate ----------
say "5. Ask for a release verdict — evidence + risk score. exit 2 = HOLD."
run fides change-gate --trail "$TRAIL_ID"
note "In CI this exit code is the whole integration — the job just fails."
beat

# ---------- 4. frameworks ----------
say "6. Map that evidence onto a regulated framework"
run fides control import --framework SOC2
run bash -c "fides control coverage | jqf '.controls[:5] | map({framework, control, coverage})'"
beat

say "7. Auditor-ready export — NIST OSCAL, not a spreadsheet"
run bash -c "fides report --framework SOC2 --format oscal | head -20"
beat

# ---------- 5. delivery ----------
say "8. And the same evidence gives you DORA metrics for free"
run bash -c 'fides metrics | jqf "{trails, attestations, deployments, compliance_rate}"'

cat <<EOF

${B}That's the loop: record → verify → gate → map → report.${R}
  trail:  $TRAIL_ID
  flow:   $FLOW_ID
  env:    $ENV_ID
  portal: $FIDES_SERVER_URL/flows

Next: open the portal and walk demo/screencasts/portal-storyboard.md,
then run 'just demo-servicenow' for the bidirectional ServiceNow proof.
EOF
