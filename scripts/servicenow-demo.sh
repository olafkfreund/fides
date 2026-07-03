#!/usr/bin/env bash
# Fides x ServiceNow — end-to-end DevGovOps demo.
#
# Proves the bidirectional, governed link live:
#   1. Fides -> ServiceNow: consume SN's MCP server (governed change_request read).
#   2. ServiceNow record carries Fides evidence: link a trail+control to a change
#      (work note + risk field written back onto the change_request).
#   3. ServiceNow -> Fides: the Now Assist grounding pack for that change.
#
# "Fides advises; ServiceNow decides."
#
# Env (no secrets in this file):
#   FIDES_SERVER_URL      e.g. https://fides.<...>.nip.io
#   FIDES_API_TOKEN       Fides API token (org-scoped)
#   FIDES_FLOW_ID         a flow with at least one green trail
#   SN_URL                https://<instance>.service-now.com
#   SN_USER / SN_PASS     ServiceNow service account (read change/cmdb + write change_request)
#   TRAIL_ID              (optional) a specific green trail; else the flow's newest is used
#   CONTROL_KEY           (optional) control to link (default SOC2-CC8.1)
set -euo pipefail

: "${FIDES_SERVER_URL:?set FIDES_SERVER_URL}"
: "${FIDES_API_TOKEN:?set FIDES_API_TOKEN}"
: "${SN_URL:?set SN_URL}"
: "${SN_USER:?set SN_USER}"
: "${SN_PASS:?set SN_PASS}"
CONTROL_KEY="${CONTROL_KEY:-SOC2-CC8.1}"

fides() { curl -fsS -H "Authorization: Bearer $FIDES_API_TOKEN" "$@"; }
snget() { curl -fsS -u "$SN_USER:$SN_PASS" "$@"; }

echo "== 1. Fides -> ServiceNow: governed MCP lookup of change requests =="
fides -H 'Content-Type: application/json' -X POST \
  -d '{"table":"change_request","limit":3}' \
  "$FIDES_SERVER_URL/api/v1/servicenow/mcp/lookup"
echo

echo "== 2. Create a dedicated demo change in ServiceNow =="
CHG_JSON=$(curl -fsS -u "$SN_USER:$SN_PASS" -H 'Content-Type: application/json' -X POST \
  -d '{"short_description":"Fides evidence demo","type":"standard"}' \
  "$SN_URL/api/now/table/change_request")
CHG=$(printf '%s' "$CHG_JSON" | python3 -c 'import sys,json;print(json.load(sys.stdin)["result"]["number"])')
echo "created $CHG"

echo "== 3. Link a green trail + control to the change (writes evidence onto the CR) =="
TRAIL_ID="${TRAIL_ID:-$(fides "$FIDES_SERVER_URL/api/v1/flows/${FIDES_FLOW_ID:?set FIDES_FLOW_ID or TRAIL_ID}/trails" \
  | python3 -c 'import sys,json;d=json.load(sys.stdin);r=d if isinstance(d,list) else d.get("trails",[]);print(next(t["id"] for t in r if not t.get("name","").startswith("red-")))')}"
echo "trail: $TRAIL_ID"
fides -H 'Content-Type: application/json' -X POST \
  -d "{\"trail_id\":\"$TRAIL_ID\",\"change_number\":\"$CHG\",\"control\":\"$CONTROL_KEY\"}" \
  "$FIDES_SERVER_URL/api/v1/servicenow/link-control"
echo
fides -H 'Content-Type: application/json' -X POST \
  -d "{\"trail_id\":\"$TRAIL_ID\",\"change_number\":\"$CHG\"}" \
  "$FIDES_SERVER_URL/api/v1/servicenow/change-check"
echo

echo "== 4. ServiceNow -> Fides: the Now Assist grounding pack =="
fides "$FIDES_SERVER_URL/api/v1/servicenow/grounding?change=$CHG" \
  | python3 -c 'import sys,json;d=json.load(sys.stdin);print("grounded:",d["grounded"]);print(d["grounding_summary"])'

echo
echo "== Demo change: $SN_URL/nav_to.do?uri=change_request.do?sysparm_query=number=$CHG =="
