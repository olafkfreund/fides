-- Seed data for Fides Core Database

-- 1. Insert Organization
INSERT INTO organizations (id, name, description, created_at)
VALUES ('5d57b8c7-4328-4e1b-93df-4161b9a918a3', 'Payments Division', 'Payments Engineering and Audits Division', CURRENT_TIMESTAMP)
ON CONFLICT (id) DO NOTHING;

-- 2. Insert Flows
INSERT INTO flows (id, org_id, name, description, tags, created_at, updated_at)
VALUES 
('f83b3e8c-8dc7-4a0b-ae95-716d1ba1f122', '5d57b8c7-4328-4e1b-93df-4161b9a918a3', 'auth-service', 'CI/CD flow for authorization endpoints', '{}'::jsonb, CURRENT_TIMESTAMP, CURRENT_TIMESTAMP),
('e102f30c-cd14-411a-8ce4-55cc28172901', '5d57b8c7-4328-4e1b-93df-4161b9a918a3', 'payment-gateway', 'CI/CD pipeline for card processing backend', '{}'::jsonb, CURRENT_TIMESTAMP, CURRENT_TIMESTAMP)
ON CONFLICT (id) DO NOTHING;

-- 3. Insert Attestation Types (Compliance templates)
INSERT INTO attestation_types (id, org_id, name, description, schema, jq_rules, created_at)
VALUES 
('d5d7b8c7-4328-4e1b-93df-4161b9a91100', '5d57b8c7-4328-4e1b-93df-4161b9a918a3', 'junit', 'JUnit Unit Testing Gate', '{}'::jsonb, ARRAY['.failures == 0', '.errors == 0'], CURRENT_TIMESTAMP),
('d5d7b8c7-4328-4e1b-93df-4161b9a91200', '5d57b8c7-4328-4e1b-93df-4161b9a918a3', 'snyk-scan', 'Snyk Vulnerability Scan Rule', '{}'::jsonb, ARRAY['.vulnerabilities.critical == 0'], CURRENT_TIMESTAMP),
('d5d7b8c7-4328-4e1b-93df-4161b9a91300', '5d57b8c7-4328-4e1b-93df-4161b9a918a3', 'secret-scan', 'Secret and Credential Exposure Check', '{}'::jsonb, ARRAY['.leaks == 0'], CURRENT_TIMESTAMP)
ON CONFLICT (id) DO NOTHING;

-- 4. Insert Environments
INSERT INTO environments (id, org_id, name, type, description, created_at)
VALUES 
('9f3c7ea1-420a-4288-ae31-716d1ba1f021', '5d57b8c7-4328-4e1b-93df-4161b9a918a3', 'Production K8s', 'K8S', 'Primary production cluster hosted on AWS EKS', CURRENT_TIMESTAMP),
('0a12cd31-df14-4a0b-bc11-55cc281728e1', '5d57b8c7-4328-4e1b-93df-4161b9a918a3', 'Production ECS Host', 'ECS', 'Fargate container host for transactional tasks', CURRENT_TIMESTAMP),
('9f3c7ea1-420a-4288-ae31-716d1ba1f0d1', '5d57b8c7-4328-4e1b-93df-4161b9a918a3', 'Development K8s', 'K8S', 'Development environment hosted on AWS EKS', CURRENT_TIMESTAMP),
('9f3c7ea1-420a-4288-ae31-716d1ba1f0a1', '5d57b8c7-4328-4e1b-93df-4161b9a918a3', 'UAT K8s', 'K8S', 'UAT environment hosted on AWS EKS', CURRENT_TIMESTAMP),
('9f3c7ea1-420a-4288-ae31-716d1ba1f0e1', '5d57b8c7-4328-4e1b-93df-4161b9a918a3', 'Production K8s (CLI)', 'K8S', 'Production environment hosted on AWS EKS', CURRENT_TIMESTAMP)
ON CONFLICT (id) DO NOTHING;

-- 5. Insert Release Policies
INSERT INTO policies (id, org_id, name, description, rules, created_at)
VALUES 
('2a12cd31-df14-4a0b-bc11-55cc281728f1', '5d57b8c7-4328-4e1b-93df-4161b9a918a3', 'production-release-rules', 'Standard release rules enforcing Unit Tests, Vulnerability scans, and Credential scans.', 
'{"provenance": {"required": true}, "attestations": [{"name": "unit-tests", "type": "junit", "rules": [".failures == 0", ".errors == 0"]}, {"name": "snyk-scan", "type": "vulnerability-scan", "rules": [".vulnerabilities.critical == 0"]}, {"name": "secret-scan", "type": "secret-scan", "rules": [".leaks == 0"]}]}'::jsonb,
CURRENT_TIMESTAMP)
ON CONFLICT (id) DO NOTHING;

-- 6. Insert Seed Users
INSERT INTO users (org_id, name, email, role, groups) VALUES
('5d57b8c7-4328-4e1b-93df-4161b9a918a3', 'Alice Vance', 'alice@company.com', 'Admin', ARRAY['admin-audit', 'payments-admins']),
('5d57b8c7-4328-4e1b-93df-4161b9a918a3', 'Bob Smith', 'bob@company.com', 'Auditor', ARRAY['compliance-auditors'])
ON CONFLICT (email) DO NOTHING;

-- 7. Insert SSO Group Mappings
INSERT INTO sso_group_mappings (org_id, external_group, role) VALUES
('5d57b8c7-4328-4e1b-93df-4161b9a918a3', 'github:payments-admins', 'Admin'),
('5d57b8c7-4328-4e1b-93df-4161b9a918a3', 'okta:compliance-auditors', 'Auditor'),
('5d57b8c7-4328-4e1b-93df-4161b9a918a3', 'gitlab:developers', 'Writer')
ON CONFLICT (org_id, external_group) DO NOTHING;

-- 8. Insert tenant LLM settings seed
INSERT INTO tenant_llm_settings (org_id, provider_name, model_name, endpoint_url)
VALUES ('5d57b8c7-4328-4e1b-93df-4161b9a918a3', 'ollama', 'llama3:8b', 'http://localhost:11434')
ON CONFLICT (org_id) DO NOTHING;

-- 9. Insert mock environment MCP server connection seed
INSERT INTO environment_mcp_servers (environment_id, name, transport, command, args, env_vars)
VALUES ('9f3c7ea1-420a-4288-ae31-716d1ba1f021', 'k8s-sensor', 'stdio', 'echo', ARRAY['{"pods": [{"name": "auth-service-5b6c", "status": "Ready", "replicas": 3, "readyReplicas": 3}]}'], '{}'::jsonb)
ON CONFLICT (environment_id, name) DO NOTHING;



