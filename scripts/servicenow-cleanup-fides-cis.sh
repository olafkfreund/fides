#!/usr/bin/env bash
# Remove CMDB configuration items Fides created on an instance it does not own.
#
# Why this exists: between the IRE fix landing and the inventory gate landing,
# Fides briefly wrote CIs into a CMDB owned by another system. Those records are
# duplicates of ones the owner already maintains, keyed differently, so they
# cannot reconcile and will never be updated again — they are inert clutter that
# makes the CMDB look like it has two of everything.
#
# It is deliberately dry-run by default and prints every record it would touch.
# Deleting from a CMDB is not reversible from here, and a CI you did not create
# may be load-bearing for somebody's dependency map or change process.
#
# Env:
#   SN_URL / SN_USER / SN_PASS   ServiceNow instance and credentials
#   SOURCE     discovery_source to target (default "Other Automated")
#   PATTERN    name filter, ServiceNow LIKE semantics (default: none = all)
#   AFTER      only records created on or after this date, YYYY-MM-DD.
#              Use it. "Other Automated" is a stock choice that other
#              integrations legitimately use, so SOURCE+PATTERN alone will
#              happily select CIs Fides never wrote — the first dry run of this
#              script matched records from three months before the incident it
#              was written to clean up.
#   APPLY=1    actually delete. Without it, nothing is written.
#
# Examples:
#   # what would be removed for the podtato leak
#   PATTERN=podtato AFTER=2026-08-17 ./scripts/servicenow-cleanup-fides-cis.sh
#   # remove it
#   PATTERN=podtato AFTER=2026-08-17 APPLY=1 ./scripts/servicenow-cleanup-fides-cis.sh
set -uo pipefail

: "${SN_URL:?set SN_URL}"
: "${SN_USER:?set SN_USER}"
: "${SN_PASS:?set SN_PASS}"

SOURCE="${SOURCE:-Other Automated}"
PATTERN="${PATTERN:-}"
AFTER="${AFTER:-}"
APPLY="${APPLY:-0}"

if [ -z "$AFTER" ] && [ "$APPLY" = 1 ]; then
  echo "Refusing to delete without AFTER=YYYY-MM-DD — see the header." >&2
  exit 2
fi

# Relations first, then the CIs they point at: deleting a CI leaves orphaned
# cmdb_rel_ci rows that are harder to find afterwards than before.
CLASSES="cmdb_ci_docker_container cmdb_ci_docker_image cmdb_ci_service_discovered"

TOTAL=0

if [ "$APPLY" != 1 ]; then
  printf '\033[33mDRY RUN\033[0m — nothing will be deleted. Re-run with APPLY=1 to act.\n\n'
fi
printf 'instance: %s\nsource:   %s\npattern:  %s\nafter:    %s\n\n' "$SN_URL" "$SOURCE" "${PATTERN:-<all>}" "${AFTER:-<any date>}"

for class in $CLASSES; do
  query="discovery_source=${SOURCE}"
  [ -n "$PATTERN" ] && query="${query}^nameLIKE${PATTERN}"
  [ -n "$AFTER" ] && query="${query}^sys_created_on>=${AFTER} 00:00:00"

  rows=$(curl -fsS -G -u "$SN_USER:$SN_PASS" \
    --data-urlencode "sysparm_query=${query}" \
    --data-urlencode 'sysparm_fields=sys_id,name,sys_created_on' \
    --data-urlencode 'sysparm_limit=500' \
    "$SN_URL/api/now/table/$class" \
    | python3 -c 'import sys,json;[print(r["sys_id"],r["sys_created_on"],r["name"]) for r in json.load(sys.stdin)["result"]]')

  n=$(printf '%s' "$rows" | grep -c . || true)
  printf '\033[1m%s\033[0m — %s record(s)\n' "$class" "$n"
  [ "${n:-0}" -eq 0 ] && { echo; continue; }
  TOTAL=$((TOTAL + n))

  printf '%s\n' "$rows" | while read -r sys_id created name; do
    [ -z "$sys_id" ] && continue
    if [ "$APPLY" = 1 ]; then
      code=$(curl -sS -o /dev/null -w '%{http_code}' -u "$SN_USER:$SN_PASS" -X DELETE \
        "$SN_URL/api/now/table/$class/$sys_id")
      # 204 is the documented success for a Table API delete.
      if [ "$code" = 204 ]; then
        printf '  \033[32mdeleted\033[0m %s  %s\n' "$created" "$name"
      else
        printf '  \033[31mFAILED\033[0m  %s  %s (HTTP %s)\n' "$created" "$name" "$code"
      fi
    else
      printf '  would delete %s  %s\n' "$created" "$name"
    fi
  done
  echo
done

printf '\033[1m%s %d record(s)\033[0m\n' "$([ "$APPLY" = 1 ] && echo Processed || echo 'Would delete')" "$TOTAL"
[ "$APPLY" = 1 ] || echo 'Re-run with APPLY=1 to delete. Check the list above first.'
