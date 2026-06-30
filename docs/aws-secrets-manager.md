# AWS Secrets Manager (live secrets backend)

`fides-server` resolves per-tenant integration `secret_path` references
(ServiceNow, webhooks, git tokens, OAuth secrets) from **AWS Secrets Manager**
when `SECRETS_PROVIDER=aws`. Core secrets (DB DSN, encryption key, API token,
portal password) remain Kubernetes `secretKeyRef`.

## Access model (IRSA, least-privilege)

Pods authenticate to AWS via **IRSA** — no static keys:

- Service account `fides-server` (annotated `eks.amazonaws.com/role-arn`).
- IAM role `fides-secrets-reader` trusts the cluster OIDC provider for that SA.
- Inline policy allows `secretsmanager:GetSecretValue` / `DescribeSecret` on
  `arn:aws:secretsmanager:eu-west-2:796973489124:secret:fides/*` only.

Both the service account and `serviceAccountName`/`SECRETS_PROVIDER` are in
`kubernetes/fides-deploy.yaml`.

## Storing a tenant secret

The `secret_path` configured for an integration is the Secrets Manager secret
id. Create it under the `fides/` prefix so the policy covers it:

```bash
aws secretsmanager create-secret --region eu-west-2 \
  --name fides/<tenant>/servicenow --secret-string '<the-secret>'
```

Then set the integration's `secret_path` (e.g. via `POST /api/v1/tenant/servicenow`)
to `fides/<tenant>/servicenow`.

## Verification

A throwaway pod using the `fides-server` SA can read a secret end-to-end:

```bash
kubectl -n fides run irsa-verify --rm -i --restart=Never --image=amazon/aws-cli \
  --overrides='{"spec":{"serviceAccountName":"fides-server"}}' \
  --command -- aws secretsmanager get-secret-value --secret-id fides/verify \
  --region eu-west-2 --query SecretString --output text
```
