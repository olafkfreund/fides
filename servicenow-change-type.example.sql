-- ServiceNow change-control attestation type (#22).
--
-- The jq policy engine evaluates this with NO engine code: an attestation of
-- type_name 'servicenow-change' carrying a change_request payload is checked
-- against these jq_rules (each must return true). POST /api/v1/servicenow/
-- change-check fetches the CR, normalizes it, records the attestation, and
-- emits compliance.evaluated — so `fides assert` (and the commit-status gate)
-- can require an approved, in-window change.
--
-- The normalized payload looks like:
--   { "found": true, "number": "CHG0030192", "state": "implement",
--     "approval": "approved", "risk": "moderate", "on_hold": false }
--
-- Replace <ORG_ID> with the tenant's organization id, or create it via the API:
--   POST /api/v1/attestation-types  { "name":"servicenow-change", "jq_rules":[ ... ] }

INSERT INTO attestation_types (org_id, name, description, schema, jq_rules)
VALUES (
    '<ORG_ID>',
    'servicenow-change',
    'Requires an approved, in-window, non-high-risk ServiceNow change request',
    '{}',
    ARRAY[
        '.found == true',
        '.approval == "approved"',
        '(.state == "implement") or (.state == "scheduled")',
        '.on_hold == false',
        '.risk != "high"'
    ]
)
ON CONFLICT (org_id, name) DO UPDATE SET
    description = EXCLUDED.description,
    jq_rules = EXCLUDED.jq_rules;
