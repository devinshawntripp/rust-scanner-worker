# K8s-Native Scan Scheduler Design

**Date:** 2026-03-06
**Status:** Approved
**Scope:** Go worker (rust-scanner-worker), Kubernetes cluster infrastructure

## Problem

The ScanRook cluster crashes when running multiple scans or large images simultaneously. All three failure modes observed:
- Worker pods OOMKilled
- Web pods become unresponsive
- Node-level resource exhaustion causing evictions across namespaces

**Root cause:** Workers execute the scanner binary as a subprocess within a long-running pod. There is no cluster-aware resource accounting — 3 workers blindly run 3 concurrent scans regardless of size, competing for ~7 GiB/node (upgrading to 15 GiB/node).

## Architecture

### Current Flow
```
Worker pod (long-running) → polls DB → downloads file → exec scanner → tails progress → uploads report → ingests findings
```

### Proposed Flow
```
Dispatcher pod (lightweight, long-running) → polls DB → creates K8s Job per scan
  → Job pod: downloads file → runs scanner → streams progress to DB → uploads report → ingests findings → exits
Dispatcher monitors Job status → handles completion/failure
```

### Key Components

**Dispatcher (replaces scanrook-worker deployment):**
- 1-2 lightweight replicas (minimal memory: 256Mi request, 512Mi limit)
- Polls `scan_jobs` for `queued` status (existing logic)
- Before creating a Job: checks artifact size via S3 `HeadObject`, determines resource tier, checks tier concurrency limits via K8s API
- Creates a K8s Job with resource requests/limits matching the tier
- Monitors Job lifecycle: Running → Succeeded/Failed
- Handles retries, stale Job cleanup, failure logging
- Requires RBAC: `create`, `get`, `list`, `watch`, `delete` on `batch/v1 Jobs` in `scanrook` namespace

**Scan Runner (K8s Job pod):**
- Same Docker image as dispatcher, invoked with `--single-job <job-id>` flag
- Scanner binary baked into Docker image at build time (installed in Dockerfile)
- On startup, runs `scanrook upgrade` to pull latest scanner version before executing
- Runs exactly one scan, then exits (exit 0 = success, exit 1 = failure)
- Contains all current scan execution logic: S3 download, scanner exec, progress tailing, report upload, finding ingestion
- Pod TTL: `ttlSecondsAfterFinished: 300` (cleaned up 5 min after completion)

## Resource Tiers

Dispatcher maps artifact size (from S3 HeadObject) to a resource tier:

| Tier | Artifact Size | CPU Req/Limit | Memory Req/Limit | Max Concurrent |
|------|--------------|---------------|-------------------|----------------|
| Small | < 500 MB | 1 / 2 | 1Gi / 3Gi | 6 (2/node) |
| Medium | 500 MB – 5 GB | 2 / 4 | 2Gi / 6Gi | 3 (1/node) |
| Large | > 5 GB | 3 / 6 | 4Gi / 10Gi | 1 cluster-wide |

**Concurrency enforcement:** Before creating a Job, dispatcher queries active Jobs by tier label (`scanrook.io/tier: small|medium|large`). If at capacity, the DB job stays `queued` and dispatcher moves on.

**RAYON_NUM_THREADS:** Set per Job env var to match CPU request, preventing thread over-subscription.

**Configuration:** Tiers stored in a ConfigMap (`scanrook-scheduler-config`) for tuning without redeployment.

## Scanner Image Strategy

**Dockerfile changes:**
```dockerfile
# Multi-stage: build Go worker + install scanner
FROM rust:latest AS scanner-build
RUN cargo install scanrook  # or download from GitHub releases

FROM golang:latest AS worker-build
# ... build Go binary ...

FROM debian:bookworm-slim
COPY --from=scanner-build /usr/local/cargo/bin/scanrook /usr/local/bin/scanrook
COPY --from=worker-build /app/worker /usr/local/bin/worker
```

**Startup sequence:**
1. Pod starts → entrypoint runs `scanrook upgrade` (auto-update to latest)
2. If upgrade fails (network issue), fall back to baked-in version
3. Execute scan with whatever version is available

## Progress Streaming

No change to the browser-facing pipeline. The scan runner pod:
1. Connects to PostgreSQL (credentials via env vars from K8s Secret)
2. Spawns scanner binary with `--progress --progress-file /tmp/progress.ndjson`
3. Tails progress file → inserts `scan_events` rows (existing `TailProgress()` code)
4. `pg_notify('job_events')` fires → SSE pushes to browser

The dispatcher does NOT participate in progress streaming. It only monitors Job status for lifecycle management.

## K8s RBAC

```yaml
apiVersion: rbac.authorization.k8s.io/v1
kind: Role
metadata:
  name: scanrook-dispatcher
  namespace: scanrook
rules:
  - apiGroups: ["batch"]
    resources: ["jobs"]
    verbs: ["create", "get", "list", "watch", "delete"]
  - apiGroups: [""]
    resources: ["pods", "pods/log"]
    verbs: ["get", "list"]
---
apiVersion: rbac.authorization.k8s.io/v1
kind: RoleBinding
metadata:
  name: scanrook-dispatcher
  namespace: scanrook
subjects:
  - kind: ServiceAccount
    name: scanrook-dispatcher
roleRef:
  kind: Role
  name: scanrook-dispatcher
  apiGroup: rbac.authorization.k8s.io
```

## Infrastructure Prerequisites

1. **Restart nodes** — pick up 15 GiB RAM / 8 cores per node
2. **Install metrics-server** — enables `kubectl top`, fixes HPAs
3. **Fix Grafana** — CrashLoopBackOff (834 restarts), debug and repair
4. **Fix Promtail** — 0/1 ready on all nodes
5. **Delete deltaguard namespace** — cleanup stale resources
6. **Update ResourceQuota** — raise limits to match new node capacity
7. **Create ServiceAccount + RBAC** for dispatcher

## Migration Path

### Phase 1: Infrastructure Prep
- Restart cluster nodes (rolling restart)
- Install metrics-server
- Fix monitoring stack (Grafana, Promtail)
- Clean up deltaguard namespace
- Update ResourceQuota

### Phase 2: Worker Refactor
- Add `--single-job <job-id>` mode to Go worker
- Extract scan execution into a standalone code path (run one job, exit)
- Update Dockerfile to bake in scanner binary + `scanrook upgrade` entrypoint
- Unit test single-job mode

### Phase 3: Dispatcher
- New `cmd/dispatcher/` entry point
- K8s client integration (client-go)
- Resource tier logic + ConfigMap
- Job creation with labels, resource requests, env vars, volumes
- Job monitoring loop (watch API)
- Stale Job cleanup
- RBAC manifests

### Phase 4: Deploy & Test
- Deploy dispatcher alongside existing workers (canary)
- Route a subset of jobs to K8s Jobs
- Monitor resource usage via Prometheus/Grafana
- Verify progress streaming works end-to-end

### Phase 5: Full Cutover & Tuning
- Remove old worker deployment
- Adjust tiers based on real scan profiles
- Set up Grafana dashboards for scan resource usage
- Document operational runbook

## Backlog Items (Not in Scope)

The following items from the feature backlog are deferred to separate designs:
- Docker registry browsing and scanning from UI
- Upload UX (cancel, drag-drop, multi-upload)
- User org management (master admin)
- Parallel enrichment pipeline optimization
- SBOM import fix
- API docs fix
- Blog/docs UI fixes
- YARA preloading
- ArgoCD deployment
- Longhorn/Hubble UI exposure
- Various scanner bugs (heuristic filter, CPE false positives, YARA warning, partial_failed status)
