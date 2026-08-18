#!/usr/bin/env bash
# Seed the Fides control catalogue into ServiceNow Policy & Compliance.
#
# The GRC sink (FIDES_SNOW_GRC_ENABLED) files each trail verdict as an
# sn_audit_control_test against the sn_compliance_control the attestation is
# evidence for. It resolves that control by NAME PREFIX -- the Fides control key
# -- and skips anything it cannot find, because seeding a customer's compliance
# catalogue is a governance decision and not a side effect of a verdict. This
# script is that deliberate step.
#
# Matching ServiceNow's own convention, seen on stock content:
#     name = "SOX-GLC-10 Quarter/year end checklist signoff"
#            ^^^^^^^^^^ key                ^^^^ description
# so controls are created as "<FIDES_KEY> <description>".
#
# Creates, per framework:
#   sn_compliance_policy            one per framework  ("Fides - DORA")
#   sn_compliance_policy_statement  one per control    (the requirement text)
#   sn_compliance_control           one per control    (what evidence attaches to)
#
# What it deliberately does NOT create: sn_grc_profile entities. Which services
# are in scope is a scoping decision for whoever runs the compliance programme,
# and a wrong guess there is harder to unpick than a missing link.
#
# Environment:
#   SERVICENOW_URL / SERVICENOW_USER / SERVICENOW_PASSWORD   admin-level
#   FIDES_SERVER_URL / FIDES_API_TOKEN                       source of the catalogue
#   APPLY=1     actually write (default: dry run, writes nothing)
#   PREFIX      policy name prefix (default "Fides")
#
# Idempotent: every object is looked up by name before it is created, so a
# re-run reports "=" and changes nothing.
#
# Reversible: every sys_id created is appended to seeded-grc-<timestamp>.txt in
# the working directory, so a seeding run can be undone precisely rather than by
# guessing which records were ours.

set -uo pipefail

: "${SERVICENOW_URL:?set SERVICENOW_URL}"
: "${SERVICENOW_USER:?set SERVICENOW_USER}"
: "${SERVICENOW_PASSWORD:?set SERVICENOW_PASSWORD}"
: "${FIDES_SERVER_URL:?set FIDES_SERVER_URL}"
: "${FIDES_API_TOKEN:?set FIDES_API_TOKEN}"

SN="${SERVICENOW_URL%/}"
PREFIX="${PREFIX:-Fides}"
APPLY="${APPLY:-0}"
LEDGER="seeded-grc-$(date +%Y%m%d-%H%M%S).txt"

# Counters live in files, not shell variables. ensure() is invoked through
# command substitution, which runs it in a SUBSHELL -- variable increments there
# are discarded, so the script's first version cheerfully printed "failed=0"
# while policies were being rejected in front of me. Reporting success for work
# that did not happen is the exact defect this whole ServiceNow effort exists to
# stamp out, so it does not get to survive in the tool that fixes it.
COUNTDIR=$(mktemp -d)
trap 'rm -rf "$COUNTDIR"' EXIT
: >"$COUNTDIR/created"; : >"$COUNTDIR/existed"; : >"$COUNTDIR/failed"
bump() { echo x >>"$COUNTDIR/$1"; }
tally() { wc -l <"$COUNTDIR/$1" | tr -d ' '; }

sn_get() {  # table, encoded query -> sys_id or empty
  curl -sS -u "${SERVICENOW_USER}:${SERVICENOW_PASSWORD}" -G \
    --data-urlencode "sysparm_query=$2" --data-urlencode 'sysparm_fields=sys_id' \
    --data-urlencode 'sysparm_limit=1' "${SN}/api/now/table/$1" \
  | python3 -c "import json,sys
try: r=json.load(sys.stdin)['result']
except Exception: r=[]
print(r[0]['sys_id'] if r else '')"
}

sn_post() { # table, json -> sys_id or empty (prints the error to stderr)
  local body
  body=$(curl -sS -u "${SERVICENOW_USER}:${SERVICENOW_PASSWORD}" \
    -H 'Content-Type: application/json' -X POST -d "$2" "${SN}/api/now/table/$1")
  printf '%s' "$body" | python3 -c "import json,sys
d=json.load(sys.stdin)
if 'result' in d and d['result'].get('sys_id'): print(d['result']['sys_id'])
else: sys.stderr.write('    ! '+json.dumps(d.get('error',d))+'\n')"
}

# ensure <table> <name-query-field> <name> <json payload> <label>
# Looks the record up by name; creates it only if absent. Echoes the sys_id.
ensure() {
  local table="$1" name="$3" payload="$4" label="$5" sys_id
  sys_id=$(sn_get "$table" "name=$name")
  if [ -n "$sys_id" ]; then
    bump existed; echo "  = ${label}: ${name}" >&2; printf '%s' "$sys_id"; return
  fi
  if [ "$APPLY" != "1" ]; then
    echo "  + ${label}: ${name}   (dry run)" >&2; printf 'DRYRUN'; return
  fi
  sys_id=$(sn_post "$table" "$payload")
  if [ -z "$sys_id" ]; then
    bump failed; echo "  ! ${label}: ${name} FAILED" >&2; return
  fi
  bump created
  echo "${table} ${sys_id} ${name}" >> "$LEDGER"
  echo "  + ${label}: ${name}" >&2
  printf '%s' "$sys_id"
}

echo "Seeding the Fides control catalogue into ${SN}"
[ "$APPLY" = "1" ] || echo "DRY RUN — nothing will be written. Set APPLY=1 to seed."
echo

# Pull the catalogue and emit one TSV line per control: key, framework, description.
CATALOGUE=$(curl -sS -k -H "Authorization: Bearer ${FIDES_API_TOKEN}" \
  "${FIDES_SERVER_URL%/}/api/v1/controls" \
  | python3 -c "
import json,sys
d=json.load(sys.stdin)
r=d if isinstance(d,list) else d.get('controls',[])
for c in r:
    if c.get('archived'): continue
    desc=(c.get('description') or c.get('name') or '').replace('\t',' ').strip()
    print('\t'.join([c['key'], c.get('framework') or 'Fides', desc]))")

if [ -z "$CATALOGUE" ]; then
  echo "No controls returned by Fides — nothing to seed." >&2
  exit 1
fi
echo "$(printf '%s\n' "$CATALOGUE" | wc -l) active control(s) in the Fides catalogue"
echo

json_str() { python3 -c "import json,sys; print(json.dumps(sys.argv[1]))" "$1"; }

declare -A POLICY_OF
while IFS=$'\t' read -r key framework desc; do
  [ -z "$key" ] && continue

  # One policy per framework, created on first sight.
  if [ -z "${POLICY_OF[$framework]:-}" ]; then
    pname="${PREFIX} - ${framework}"
    # state=draft deliberately. Posting state=published with active=true is
    # rejected by the business rule "Enforce fields" -- publishing a policy is a
    # reviewed action in ServiceNow, not something a seeding script performs.
    # Stock policies on the instance sit at draft/inactive too. Whoever owns the
    # compliance programme publishes these.
    ppayload=$(python3 -c "
import json,sys
print(json.dumps({'name':sys.argv[1],
 'description':'Controls evidenced continuously by Fides from CI/CD provenance. '
               'Each verdict is filed as an sn_audit_control_test against the control it satisfies.',
 'state':'draft'}))" "$pname")
    POLICY_OF[$framework]=$(ensure sn_compliance_policy name "$pname" "$ppayload" "policy")
  fi

  policy_id="${POLICY_OF[$framework]}"

  # ServiceNow's convention: "<KEY> <description>". The sink resolves on the
  # key prefix, so this name is load-bearing -- see grcSinkResolve in
  # pkg/servicenow/grc.go and the test that pins it.
  full_name="${key} ${desc}"

  # A statement carries no 'policy' field -- posting one is accepted and
  # silently discarded, the same Table API behaviour that hid the
  # discovery_source defect. The link is an m2m row instead, created below:
  #   sn_compliance_m2m_policy_policy_statement (document=policy, content=statement)
  # Missing that is why an earlier run left six policies with nothing in them.
  spayload=$(python3 -c "
import json,sys
name,desc=sys.argv[1],sys.argv[2]
print(json.dumps({'name':name,'description':desc,'state':'published','active':'true'}))" "$full_name" "$desc")
  stmt_id=$(ensure sn_compliance_policy_statement name "$full_name" "$spayload" "statement")

  cpayload=$(python3 -c "
import json,sys
name,desc,content=sys.argv[1],sys.argv[2],sys.argv[3]
d={'name':name,'description':desc,
   'additional_information':'Evidenced automatically by Fides. Control tests are written to '
                            'sn_audit_control_test carrying the trail id, attestation and content hash.',
   'classification':'Detective','frequency':'continuous','active':'true'}
if content and content!='DRYRUN': d['content']=content
print(json.dumps(d))" "$full_name" "$desc" "$stmt_id")
  ensure sn_compliance_control name "$full_name" "$cpayload" "control" >/dev/null

  # Attach the statement to its framework policy. Without this the policy is an
  # empty container: it lists no requirements, so it cannot be meaningfully
  # reviewed or approved, and the framework grouping exists in name only.
  if [ "$APPLY" = "1" ] && [ -n "$stmt_id" ] && [ "$stmt_id" != "DRYRUN" ] \
     && [ -n "$policy_id" ] && [ "$policy_id" != "DRYRUN" ]; then
    existing=$(sn_get sn_compliance_m2m_policy_policy_statement "document=${policy_id}^content=${stmt_id}")
    if [ -z "$existing" ]; then
      link=$(sn_post sn_compliance_m2m_policy_policy_statement \
        "{\"document\":\"${policy_id}\",\"content\":\"${stmt_id}\"}")
      if [ -n "$link" ]; then
        bump created
        echo "sn_compliance_m2m_policy_policy_statement ${link} ${full_name}" >> "$LEDGER"
        echo "  + link: ${full_name} -> ${pname:-policy}" >&2
      else
        bump failed; echo "  ! link: ${full_name} FAILED" >&2
      fi
    else
      bump existed
    fi
  fi

done <<< "$CATALOGUE"

echo
CREATED=$(tally created); EXISTED=$(tally existed); FAILED=$(tally failed)
echo "created=${CREATED} existed=${EXISTED} failed=${FAILED}"
if [ "$APPLY" = "1" ] && [ "$CREATED" -gt 0 ]; then
  echo "Every created record is listed in ${LEDGER} — delete them from there to undo."
fi
exit "$FAILED"
