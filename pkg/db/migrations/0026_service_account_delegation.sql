-- A service account may be allowed to record approvals on behalf of a named
-- human without being able to administer the organisation.
--
-- Delegation previously required the Admin role. That forced a choice between
-- two things that should not be coupled: a deploy tool that records who signed
-- off, and a credential that can create service accounts, rewrite controls and
-- register users. Least privilege lost, because the alternative was approvals
-- that the change gate silently refuses to count.
--
-- Default FALSE, so no existing credential gains anything by upgrading.
ALTER TABLE service_accounts
    ADD COLUMN IF NOT EXISTS may_delegate_approvals BOOLEAN NOT NULL DEFAULT FALSE;
