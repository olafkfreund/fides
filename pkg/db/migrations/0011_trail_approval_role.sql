-- Segregation-of-duties role for trail approvals (existing databases).
-- Separates reviewer sign-offs ('approver') from the identity that performs
-- the deployment ('deployer'), so the change gate / `fides approve` can prove
-- committer != approver != deployer (PCI-DSS 4.0 / SOX ITGC).
ALTER TABLE trail_approvals ADD COLUMN IF NOT EXISTS role VARCHAR(20) NOT NULL DEFAULT 'approver';
