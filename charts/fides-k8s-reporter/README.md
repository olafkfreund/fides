# fides-k8s-reporter

A Helm chart that periodically snapshots the running workloads in a Kubernetes
cluster (or a single namespace) and reports them to a **Fides** server. Fides
diffs successive snapshots to surface **config/runtime drift** and **shadow
changes** (things running that were never recorded as provenance).

It is a thin, read-only CronJob wrapper around `fides snapshot k8s` — the
snapshot + diff logic already lives in Fides (`POST /api/v1/snapshots`,
environment snapshots, drift re-evaluation).

## How it works

```text
CronJob ──runs──▶ fides snapshot k8s --env <id> [--namespace <ns>]
                     └─ GET /api/v1/pods from the API server   ──▶  POST /api/v1/snapshots
                        (in-cluster ServiceAccount token)           (Fides diffs vs the
                                                                     previous snapshot)
```

## Prerequisites

1. A reachable Fides server and an **API token** (service-account or session).
2. A Fides **environment** to report into — create it once and note its UUID:

   ```bash
   fides env create --name my-cluster --type k8s   # or via the portal
   ```

3. The **reporter image** (just the `fides` CLI — it reads the API server
   directly, so no `kubectl` is baked in), built from `Dockerfile.reporter`:

   ```bash
   docker build -f Dockerfile.reporter -t ghcr.io/<you>/fides-k8s-reporter:1.0.0 .
   docker push ghcr.io/<you>/fides-k8s-reporter:1.0.0
   # (for k3d/local: k3d image import ghcr.io/<you>/fides-k8s-reporter:1.0.0 -c <cluster>)
   ```

## Install

```bash
# 1) API-token secret (the chart never templates the token itself)
kubectl create namespace fides-reporter
kubectl -n fides-reporter create secret generic fides-reporter-token \
  --from-literal=token='<your-fides-api-token>'

# 2) install
helm install k8s-reporter charts/fides-k8s-reporter \
  --namespace fides-reporter \
  --set image.repository=ghcr.io/<you>/fides-k8s-reporter \
  --set image.tag=1.0.0 \
  --set fides.serverUrl=https://fides.example.com \
  --set fides.environmentId=<environment-uuid>
```

### Least-privilege (single namespace)

```bash
helm install k8s-reporter charts/fides-k8s-reporter \
  --namespace my-app \
  --set serviceAccount.permissionScope=namespace \
  --set fides.namespace=my-app \
  --set fides.serverUrl=https://fides.example.com \
  --set fides.environmentId=<environment-uuid> \
  --set image.repository=ghcr.io/<you>/fides-k8s-reporter --set image.tag=1.0.0
```

This binds a namespaced `Role` (pods get/list in that namespace only) instead of
a cluster-wide `ClusterRole`.

## Key values

| Key | Default | Notes |
|-----|---------|-------|
| `image.repository` / `image.tag` | ghcr.io/olafkfreund/fides-k8s-reporter / appVersion | your reporter image |
| `cronSchedule` | `*/10 * * * *` | how often to snapshot |
| `serviceAccount.permissionScope` | `cluster` | `cluster` (ClusterRole, all ns) or `namespace` (Role) |
| `fides.serverUrl` | `""` | **required** |
| `fides.environmentId` | `""` | **required** — Fides environment UUID |
| `fides.namespace` | `""` | limit to one namespace; **required** when scope=namespace |
| `fides.apiToken.secretName` / `secretKey` | `fides-reporter-token` / `token` | your out-of-band Secret |

## Security

Read-only (`pods: get/list`), runs as non-root (65532) with
`readOnlyRootFilesystem`, all capabilities dropped, `RuntimeDefault` seccomp.
The API token is referenced from a Secret you create; it is never in the chart.
