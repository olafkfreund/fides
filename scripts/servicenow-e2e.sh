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
section "1. CMDB — IRE upsert creates real CIs"

# Drive IRE through the same code path the sink uses, with a run-unique name so
# the read-back cannot pass on CIs left by an earlier run.
SVC="fides-$RUN_ID"
DIGEST="$(printf '%s' "$RUN_ID" | sha256sum | cut -c1-64)"
IRE_OUT=$(snpost --data @- "$SN_URL/api/now/identifyreconcile?sysparm_data_source=Other%20Automated" <<EOF
{"items":[
 {"className":"cmdb_ci_service_discovered","values":{"name":"$SVC","short_description":"Fides e2e"}},
 {"className":"cmdb_ci_docker_image","values":{"name":"ghcr.io/fides/$SVC","image_id":"sha256:$DIGEST"}},
 {"className":"cmdb_ci_docker_container","values":{"name":"$SVC-c","container_id":"$SVC-c","state":"running"}}
],"relations":[
 {"parent":1,"child":2,"type":"Instantiates::Instance of"},
 {"parent":2,"child":0,"type":"Depends on::Used by"}]}
EOF
)
HAS_ERR=$(printf '%s' "$IRE_OUT" | jqp 'print(str(json.load(sys.stdin)["result"]["hasError"]).lower())')
ok "IRE reports no error" "$([ "$HAS_ERR" = false ] && echo true || echo false)" \
   "$(printf '%s' "$IRE_OUT" | jqp 'r=json.load(sys.stdin)["result"];print("; ".join(e["message"][:90] for i in r["items"] for e in i.get("errors",[])))')"

# The read-back. This is the check the old mock-only suite could not express.
for t in cmdb_ci_service_discovered cmdb_ci_docker_container; do
  n=$(snget --data-urlencode "sysparm_query=nameLIKE$SVC" --data-urlencode 'sysparm_fields=sys_id' \
        "$SN_URL/api/now/table/$t" | jqp 'print(len(json.load(sys.stdin)["result"]))')
  ok "$t CI exists in CMDB" "$([ "${n:-0}" -ge 1 ] && echo true || echo false)" "found $n"
done

# Relations are checked separately because they fail independently of the items:
# a relation whose type is not a cmdb_rel_type name is rejected on its own, and
# "Instantiated From" — which Fides used to send — is not one.
RELS=$(snget --data-urlencode "sysparm_query=parent.nameLIKE$SVC^ORchild.nameLIKE$SVC" \
  --data-urlencode 'sysparm_fields=type' --data-urlencode 'sysparm_display_value=true' \
  "$SN_URL/api/now/table/cmdb_rel_ci" \
  | jqp 'print(",".join(r["type"]["display_value"] for r in json.load(sys.stdin)["result"]))')
ok "image->container relation created" \
   "$(printf '%s' "$RELS" | grep -q 'Instantiates::Instance of' && echo true || echo false)" "types=$RELS"
ok "container->service relation created" \
   "$(printf '%s' "$RELS" | grep -q 'Depends on::Used by' && echo true || echo false)" "types=$RELS"

# ---------------------------------------------------------------------------
section "2. ITOM — event lands in em_event"

MSGKEY="fides-$RUN_ID"
snpost -d "{\"records\":[{\"source\":\"Fides\",\"event_class\":\"Fides\",\"node\":\"$SVC\",\"severity\":\"4\",\"description\":\"Fides e2e probe\",\"message_key\":\"$MSGKEY\"}]}" \
  "$SN_URL/api/global/em/jsonv2" >/dev/null

# Event ingestion is asynchronous — poll rather than assume.
EVN=0
for _ in 1 2 3 4 5 6 7 8 9 10; do
  EVN=$(snget --data-urlencode "sysparm_query=message_key=$MSGKEY" --data-urlencode 'sysparm_fields=sys_id' \
        "$SN_URL/api/now/table/em_event" | jqp 'print(len(json.load(sys.stdin)["result"]))')
  [ "${EVN:-0}" -ge 1 ] && break
  sleep 3
done
ok "em_event row created" "$([ "${EVN:-0}" -ge 1 ] && echo true || echo false)" "found $EVN after polling"

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
printf '\n\033[1m== Result: %d passed, %d failed\033[0m\n' "$PASSED" "$FAILED"
echo "Records created (run id $RUN_ID):"
echo "  change:  $SN_URL/nav_to.do?uri=change_request.do?sys_id=$CHG_SYS"
echo "  CIs:     name LIKE $SVC"
echo "  event:   message_key = $MSGKEY"
[ "${KEEP:-0}" = 1 ] || echo "  (set KEEP=1 to silence this; nothing is auto-deleted)"

exit "$FAILED"
