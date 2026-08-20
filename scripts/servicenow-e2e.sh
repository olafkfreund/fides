#!/usr/bin/env bash
# Fides x ServiceNow — live end-to-end verification.
#
# The difference between this and servicenow-demo.sh is the assertion model.
# The demo drives the surfaces and prints what Fides says. This script drives
# them and then asks *ServiceNow* what happened, because a 200 from Fides only
# proves Fides was happy.
#
# That distinction is not academic. The CMDB sink shipped for months posting an
# IRE payload that ServiceNow rejected in full, and reported success every time,
# because IRE answers HTTP 200 with the rejections buried in the body. Nothing
# that trusted a Fides status code could ever have seen it. Every check below
# therefore ends in a read-back through ServiceNow's own Table API.
#
# Env:
#   FIDES_SERVER_URL   e.g. https://fides.<host>
#   FIDES_API_TOKEN    Fides API token (org-scoped)
#   FIDES_FLOW_ID      a flow with at least one green trail
#   SN_URL             https://<instance>.service-now.com
#   SN_USER / SN_PASS  ServiceNow service account
#   KEEP=1             keep the records created (default: report them for cleanup)
#   CMDB_INVENTORY=1   assert Fides writes CMDB CIs (only where Fides owns the
#                      CMDB; on an ARC-owned instance leave unset and the suite
#                      asserts the gate holds instead)
#
# Exit code is the number of failed checks, so CI can gate on it.
set -uo pipefail

: "${FIDES_SERVER_URL:?set FIDES_SERVER_URL}"
: "${FIDES_API_TOKEN:?set FIDES_API_TOKEN}"
: "${SN_URL:?set SN_URL}"
: "${SN_USER:?set SN_USER}"
: "${SN_PASS:?set SN_PASS}"

RUN_ID="e2e-$(date +%s)"
FAILED=0
SKIPPED=0
PASSED=0

fides()  { curl -fsS -H "Authorization: Bearer $FIDES_API_TOKEN" "$@"; }
snget()  { curl -fsS -G -u "$SN_USER:$SN_PASS" "$@"; }
snpost() { curl -fsS -u "$SN_USER:$SN_PASS" -H 'Content-Type: application/json' -X POST "$@"; }
jqp()    { python3 -c "import sys,json;$1"; }

# ok <name> <condition-result> [detail]
ok() {
  if [ "$2" = "true" ]; then
    printf '  \033[32mPASS\033[0m %s\n' "$1"; PASSED=$((PASSED+1))
  else
    printf '  \033[31mFAIL\033[0m %s%s\n' "$1" "${3:+ — $3}"; FAILED=$((FAILED+1))
  fi
}

# skip <name> <why> — not a pass and not a failure. A suite that reports red for
# a deliberately disabled feature trains people to ignore it, which costs more
# than the check is worth.
skip() { printf '  \033[33mSKIP\033[0m %s — %s\n' "$1" "$2"; SKIPPED=$((SKIPPED+1)); }

section() { printf '\n\033[1m== %s\033[0m\n' "$1"; }

# ---------------------------------------------------------------------------
section "0. Preflight — credential and per-surface reachability"

for probe in "sys_user:auth" "change_request:ITSM" "cmdb_ci:CMDB" \
             "em_event:ITOM" "sys_attachment:attachments" "sn_mcp_server:MCP"; do
  table="${probe%%:*}"; label="${probe##*:}"
  code=$(curl -sS -o /dev/null -w '%{http_code}' -u "$SN_USER:$SN_PASS" \
         "$SN_URL/api/now/table/$table?sysparm_limit=1")
  ok "$label reachable ($table)" "$([ "$code" = 200 ] && echo true || echo false)" "HTTP $code"
done

# ---------------------------------------------------------------------------
section "1-2. CMDB + ITOM sinks — driven through Fides, end to end"

# These two surfaces are NOT exercised by calling ServiceNow directly. The
# whole point is the chain Fides actually runs in production:
#
#   POST /api/v1/snapshots -> snapshot.reported    -> outbox -> CMDBSink -> IRE
#                          -> snapshot.noncompliant -> outbox -> ITOMSink -> em_event
#
# Reporting an artifact digest Fides has never seen makes it a shadow change,
# which fires both events from one call. Anything that only curls ServiceNow
# validates the payload contract but leaves the sink path untested — and the
# sink path is where the CMDB bug lived.
SVC="fides-$RUN_ID"
DIGEST="$(printf '%s' "$RUN_ID" | sha256sum | cut -c1-64)"

ENV_ID=$(fides -H 'Content-Type: application/json' -X POST \
  -d "{\"name\":\"$SVC-env\",\"type\":\"K8S\",\"description\":\"Fides e2e, safe to delete\"}" \
  "$FIDES_SERVER_URL/api/v1/environments" | jqp 'print(json.load(sys.stdin)["id"])')
ok "environment created in Fides" "$([ -n "$ENV_ID" ] && echo true || echo false)" "$ENV_ID"

SNAP=$(fides -H 'Content-Type: application/json' -X POST \
  -d "{\"environment_id\":\"$ENV_ID\",\"artifacts\":[{\"sha256\":\"$DIGEST\",\"service_name\":\"$SVC\"}]}" \
  "$FIDES_SERVER_URL/api/v1/snapshots")
SHADOWS=$(printf '%s' "$SNAP" | jqp 'print(len(json.load(sys.stdin).get("shadow_changes") or []))')
ok "snapshot reports the unregistered digest as a shadow" \
   "$([ "${SHADOWS:-0}" -ge 1 ] && echo true || echo false)" \
   "shadows=$SHADOWS (both sink events depend on this)"

# The outbox dispatcher is asynchronous; give it room before concluding.
echo "  waiting for the outbox dispatcher..."
sleep 20

# CI-inventory writes are opt-in (FIDES_SNOW_CMDB_ENABLED on the server), because
# on a shared instance the CMDB already has an owner. Set CMDB_INVENTORY=1 here
# to assert they happen; otherwise assert only that the sink stayed quiet, which
# is the correct behaviour on an ARC-owned instance.
if [ "${CMDB_INVENTORY:-0}" = 1 ]; then
  # The read-back the old mock-only suite could not express: it fails whenever
  # IRE rejects the sink's payload, which it did — silently, inside an HTTP 200
  # — for every release before the fix.
  for t in cmdb_ci_service_discovered cmdb_ci_docker_container; do
    n=0
    for _ in 1 2 3 4 5 6 7 8 9 10; do
      n=$(snget --data-urlencode "sysparm_query=nameLIKE$SVC" --data-urlencode 'sysparm_fields=sys_id' \
            "$SN_URL/api/now/table/$t" | jqp 'print(len(json.load(sys.stdin)["result"]))')
      [ "${n:-0}" -ge 1 ] && break
      sleep 6
    done
    ok "CMDB sink created $t" "$([ "${n:-0}" -ge 1 ] && echo true || echo false)" "found $n"
  done

  # Relations are checked separately because they fail independently of the
  # items: a relation whose type is not a cmdb_rel_type name is rejected on its
  # own, and "Instantiated From" — which Fides used to send — is not one.
  RELS=$(snget --data-urlencode "sysparm_query=parent.nameLIKE$SVC^ORchild.nameLIKE$SVC" \
    --data-urlencode 'sysparm_fields=type' --data-urlencode 'sysparm_display_value=true' \
    "$SN_URL/api/now/table/cmdb_rel_ci" \
    | jqp 'print(",".join(r["type"]["display_value"] for r in json.load(sys.stdin)["result"]))')
  ok "image->container relation created" \
     "$(printf '%s' "$RELS" | grep -q 'Instantiates::Instance of' && echo true || echo false)" "types=$RELS"
  ok "container->service relation created" \
     "$(printf '%s' "$RELS" | grep -q 'Depends on::Used by' && echo true || echo false)" "types=$RELS"
else
  # Assert the gate actually holds. A disabled feature that still writes is
  # worse than one that never worked, because nobody is looking.
  LEAKED=$(snget --data-urlencode "sysparm_query=nameLIKE$SVC" --data-urlencode 'sysparm_fields=sys_id' \
    "$SN_URL/api/now/table/cmdb_ci" | jqp 'print(len(json.load(sys.stdin)["result"]))')
  ok "CMDB inventory gate holds (no CIs written)" \
     "$([ "${LEAKED:-0}" -eq 0 ] && echo true || echo false)" "found $LEAKED unexpected CIs"
  skip "CMDB sink CI/relation assertions" "inventory disabled; set CMDB_INVENTORY=1 when Fides owns the CMDB"
fi

# ---------------------------------------------------------------------------
# ITOMSink stamps node with the environment id and source with Fides-Compliance,
# so a hit here can only have come from the sink — not from this script.
EVN=0
for _ in 1 2 3 4 5 6 7 8 9 10; do
  EVN=$(snget --data-urlencode "sysparm_query=node=$ENV_ID^source=Fides-Compliance" \
        --data-urlencode 'sysparm_fields=sys_id' "$SN_URL/api/now/table/em_event" \
        | jqp 'print(len(json.load(sys.stdin)["result"]))')
  [ "${EVN:-0}" -ge 1 ] && break
  sleep 6
done
ok "ITOM sink wrote em_event for the shadow" "$([ "${EVN:-0}" -ge 1 ] && echo true || echo false)" \
   "found $EVN with node=$ENV_ID"

# ---------------------------------------------------------------------------
section "3-5. ITSM — change check, gate write-back, control linkage"

CHG_SYS=$(snpost -d "{\"short_description\":\"Fides e2e $RUN_ID\",\"type\":\"standard\"}" \
  "$SN_URL/api/now/table/change_request" | jqp 'print(json.load(sys.stdin)["result"]["sys_id"])')
CHG=$(snget --data-urlencode "sysparm_query=sys_id=$CHG_SYS" --data-urlencode 'sysparm_fields=number' \
  "$SN_URL/api/now/table/change_request" | jqp 'print(json.load(sys.stdin)["result"][0]["number"])')
echo "  change: $CHG ($CHG_SYS)"

TRAIL_ID="${TRAIL_ID:-$(fides "$FIDES_SERVER_URL/api/v1/flows/${FIDES_FLOW_ID:?set FIDES_FLOW_ID or TRAIL_ID}/trails" \
  | jqp 'd=json.load(sys.stdin);r=d if isinstance(d,list) else d.get("trails",[]);print(r[0]["id"] if r else "")')}"
ok "a trail is available to attest" "$([ -n "$TRAIL_ID" ] && echo true || echo false)"

if [ -n "$TRAIL_ID" ]; then
  fides -H 'Content-Type: application/json' -X POST \
    -d "{\"trail_id\":\"$TRAIL_ID\",\"change_number\":\"$CHG\"}" \
    "$FIDES_SERVER_URL/api/v1/servicenow/change-check" >/dev/null 2>&1
  ok "change-check accepted" "$([ $? -eq 0 ] && echo true || echo false)"

  fides -H 'Content-Type: application/json' -X POST \
    -d "{\"trail_id\":\"$TRAIL_ID\",\"change_number\":\"$CHG\",\"control\":\"${CONTROL_KEY:-SOC2-CC8.1}\"}" \
    "$FIDES_SERVER_URL/api/v1/servicenow/link-control" >/dev/null 2>&1

  # Read the work notes back off the change. A work note is a journal field, so
  # it is only visible via sys_journal_field or the record's own work_notes.
  NOTES=$(snget --data-urlencode "sysparm_query=element_id=$CHG_SYS^element=work_notes" \
    --data-urlencode 'sysparm_fields=value' "$SN_URL/api/now/table/sys_journal_field" \
    | jqp 'print(" ".join(r["value"] for r in json.load(sys.stdin)["result"]))')
  ok "evidence written onto the change as a work note" \
     "$(printf '%s' "$NOTES" | grep -qi 'fides' && echo true || echo false)" \
     "work_notes did not mention Fides"
fi

# ---------------------------------------------------------------------------
section "6. CMDB anchoring — attestation attached to a record"

ATT=$(curl -fsS -u "$SN_USER:$SN_PASS" -X POST -H 'Content-Type: application/json' \
  --data '{"probe":"fides-e2e"}' \
  "$SN_URL/api/now/attachment/file?table_name=change_request&table_sys_id=$CHG_SYS&file_name=fides-$RUN_ID.json" \
  | jqp 'print(json.load(sys.stdin)["result"]["sys_id"])' 2>/dev/null)
SIZE=$(snget --data-urlencode "sysparm_query=sys_id=$ATT" --data-urlencode 'sysparm_fields=size_bytes' \
  "$SN_URL/api/now/table/sys_attachment" | jqp 'r=json.load(sys.stdin)["result"];print(r[0]["size_bytes"] if r else 0)')
ok "attachment stored with non-zero size" "$([ "${SIZE:-0}" -gt 0 ] && echo true || echo false)" "size=$SIZE"

# ---------------------------------------------------------------------------
section "7-8. Grounding and governed MCP lookup"

GROUND=$(fides "$FIDES_SERVER_URL/api/v1/servicenow/grounding?change=$CHG" 2>/dev/null \
  | jqp 'print(str(json.load(sys.stdin).get("grounded")).lower())' 2>/dev/null)
ok "grounding pack returned for $CHG" "$([ -n "$GROUND" ] && echo true || echo false)" "grounded=$GROUND"

# Cross-check: the MCP lookup must agree with a direct Table API query. If they
# disagree, the governed path is filtering or failing silently.
MCP_N=$(fides -H 'Content-Type: application/json' -X POST -d '{"table":"change_request","limit":3}' \
  "$FIDES_SERVER_URL/api/v1/servicenow/mcp/lookup" 2>/dev/null \
  | jqp 'd=json.load(sys.stdin);print(len(d.get("records",d.get("result",[]))))' 2>/dev/null)
ok "MCP lookup returns change_request rows" "$([ "${MCP_N:-0}" -ge 1 ] && echo true || echo false)" "rows=$MCP_N"

# ---------------------------------------------------------------------------
section "GRC control tests (sn_audit_control_test)"

# Fides files a trail verdict as a control test only when FIDES_SNOW_GRC_ENABLED
# is set on the server AND the Fides control key exists in the ServiceNow
# catalogue. Both are deployment decisions, so this asserts whichever state the
# instance is actually in rather than demanding one. The check that always runs
# is the negative one: control_effectiveness must never be set by Fides, because
# ServiceNow accepts it, ignores it, and reads back "none".

CTL_KEY=$(fides "$FIDES_SERVER_URL/api/v1/controls" 2>/dev/null \
  | jqp 'd=json.load(sys.stdin);r=d if isinstance(d,list) else d.get("controls",[]);print(r[0]["key"] if r else "")' 2>/dev/null)

if [ -z "$CTL_KEY" ]; then
  skip "GRC control test filed" "no Fides controls defined for this org"
else
  SN_CTL=$(snget --data-urlencode "sysparm_query=nameSTARTSWITH$CTL_KEY" \
    --data-urlencode 'sysparm_fields=sys_id' --data-urlencode 'sysparm_limit=1' \
    "$SN_URL/api/now/table/sn_compliance_control" 2>/dev/null \
    | jqp 'r=json.load(sys.stdin)["result"];print(r[0]["sys_id"] if r else "")' 2>/dev/null)

  if [ -z "$SN_CTL" ]; then
    skip "GRC control test filed" "control $CTL_KEY not seeded in sn_compliance_control"
  else
    TESTS=$(snget --data-urlencode "sysparm_query=control=$SN_CTL^actual_resultsLIKE[fides:" \
      --data-urlencode 'sysparm_fields=sys_id,design_effectiveness,operation_effectiveness,control_effectiveness' \
      "$SN_URL/api/now/table/sn_audit_control_test" 2>/dev/null)
    N=$(printf '%s' "$TESTS" | jqp 'print(len(json.load(sys.stdin)["result"]))' 2>/dev/null)

    if [ "${N:-0}" -eq 0 ]; then
      skip "GRC control test filed" "none yet for $CTL_KEY (FIDES_SNOW_GRC_ENABLED unset?)"
    else
      ok "GRC control test filed for $CTL_KEY" true "n=$N"

      # The derived field must be computed by ServiceNow, never written by
      # Fides. If Fides wrote it, the two inputs would be empty while the
      # rollup carried a value -- that inversion is the tell.
      BAD=$(printf '%s' "$TESTS" | jqp 'r=json.load(sys.stdin)["result"];print(sum(1 for x in r if not x.get("design_effectiveness") and x.get("control_effectiveness") not in ("","none")))' 2>/dev/null)
      ok "control_effectiveness left to ServiceNow to derive" \
        "$([ "${BAD:-1}" -eq 0 ] && echo true || echo false)" "written-directly=$BAD"

      # Idempotency: the [fides:<trail>:<attestation>] marker is unique per
      # verdict, so duplicates mean redelivery is accumulating audit records.
      DUPS=$(snget --data-urlencode "sysparm_query=control=$SN_CTL^actual_resultsLIKE[fides:" \
        --data-urlencode 'sysparm_fields=actual_results' --data-urlencode 'sysparm_limit=100' \
        "$SN_URL/api/now/table/sn_audit_control_test" 2>/dev/null \
        | jqp 'import re;r=json.load(sys.stdin)["result"];m=[re.search(r"\[fides:[^]]*\]",x.get("actual_results","")) for x in r];k=[x.group(0) for x in m if x];print(len(k)-len(set(k)))' 2>/dev/null)
      ok "no duplicate control tests per verdict" \
        "$([ "${DUPS:-1}" -eq 0 ] && echo true || echo false)" "duplicates=$DUPS"
    fi
  fi
fi

# ---------------------------------------------------------------------------
printf '\n\033[1m== Result: %d passed, %d failed, %d skipped\033[0m\n' "$PASSED" "$FAILED" "$SKIPPED"
echo "Records created (run id $RUN_ID):"
echo "  change:  $SN_URL/nav_to.do?uri=change_request.do?sys_id=$CHG_SYS"
echo "  CIs:     name LIKE $SVC"
echo "  events:  em_event node = $ENV_ID"
echo "  env:     Fides environment $ENV_ID"

# Archive the environment this run created, unless KEEP=1 asked to inspect it.
#
# Control coverage divides by the number of live environments, so leaving one
# behind every week quietly lowered every control: five abandoned runs had DORA
# reading 40% when the honest figure was 60%. Archiving is not deleting -- the
# snapshot and events this run recorded stay queryable as evidence, the row
# keeps its id, and `fides env unarchive --env $ENV_ID` puts it back. It simply
# stops a test fixture counting as a production environment.
if [ "${KEEP:-0}" = 1 ]; then
  echo "  (KEEP=1: environment left active for inspection)"
else
  if fides env archive --env "$ENV_ID" >/dev/null 2>&1; then
    echo "  (environment archived; evidence kept. KEEP=1 to leave it active)"
  else
    # An older server has no archive endpoint. Not worth failing a green run.
    echo "  (could not archive $ENV_ID -- archive it by hand so coverage stays honest)"
  fi
fi

exit "$FAILED"
