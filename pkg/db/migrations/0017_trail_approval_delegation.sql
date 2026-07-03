-- On-behalf-of approval delegation for trail approvals (existing databases).
-- When a service token records a human approval on behalf of a logged-in user
-- (portal flow, gated by FIDES_DELEGATED_APPROVAL_ENABLED + an Admin service
-- principal), delegated_by captures the delegating service principal's identity
-- for audit, while approved_by/approver_kind reflect the attributed human.
ALTER TABLE trail_approvals ADD COLUMN IF NOT EXISTS delegated_by VARCHAR(255);
