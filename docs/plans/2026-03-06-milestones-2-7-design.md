# ScanRook Milestones 2-7 Design

**Date:** 2026-03-06
**Status:** Approved
**Execution:** 4 parallel Claude Code tabs

---

## Decisions Log

| Decision | Choice | Rationale |
|----------|--------|-----------|
| ArgoCD scope | All namespaces, scanrook first | User preference — start focused, expand later |
| Monitoring | Fix namespace refs + add dashboards | Existing manifests reference deleted `deltaguard` namespace |
| Longhorn/Hubble domains | `*.apps.onetripp.com` | Consistent with existing minio pattern |
| Upload UX | react-dropzone | Well-maintained, small bundle |
| Scanner fixes | Conservative patches | Aggressive refactor deferred to new M7 |
| Registry support | Any OCI-compliant registry | Distribution spec — universal |
| Registry credentials | Per-org in DB (encrypted) | UI-configurable, worker reads from DB |
| Benchmarks | Both scan time + load test | Thorough final verification |
| Parallelism | 4 Claude Code tabs | Maximum throughput |
| Cancel scan | Tab 2 owns full stack (UI + dispatcher API) | Avoids cross-tab dependency |
| Light summary | Counts only (8000 critical, 400 medium, etc.) | Quick totals without enrichment detail |
| Admin panel | Existing admin_override role, tighten visibility | Role hierarchy: super admin > org admin > user |
| Caddy deploy | SSH + docker compose restart | Fully autonomous |
| Docker auth | Already configured | Push to devintripp/* |
| Cluster access | SSH to dg-node1/2/3 | Use cluster-manager agent |
| Scanner version | v1.12.2 patch release | Bug fixes only |
| Image tagging | Semantic versioning; scanner gets git tags + GitHub releases | Everything else semver suffix only |
| K8s manifest dir | Rename k8s/deltaguard/ → k8s/scanrook/ | Clean up naming inconsistency |
| ArgoCD manifests | New k8s/argocd/ dir + Helm install | Clean separation |

---

## Milestone 1 Closeout (Prerequisite — Tab 1)

### Task 20: Concurrent Scan Verification
- Upload 3+ files simultaneously via the UI
- Verify tier enforcement: small tier allows up to 6, medium up to 3, large up to 1
- Check that excess jobs stay queued and dispatch when capacity frees

### Task 21: Old Worker Cleanup + Merge
- Delete `scanrook-worker` deployment (currently at 0 replicas)
- Remove `worker-deployment.yaml` from k8s manifests
- Merge `feature/k8s-job-scheduler` → `main` in `rust-scanner-worker`
- Merge `feature/k8s-job-scheduler` → `main` in `scanrook-ui`

---

## Milestone 2: Infrastructure & Observability (Tab 1, after M1)

**Repos:** scanrook-ui (manifests), cluster operations via SSH

### Phase 2.1: Directory Rename
- Rename `k8s/deltaguard/` → `k8s/scanrook/`
- Update all internal references (kustomization.yaml, any scripts)

### Phase 2.2: Monitoring Fix
- Update `prometheus-config.yaml`: change `deltaguard` → `scanrook` in scrape targets
- Update `promtail-config.yaml`: change `deltaguard` → `scanrook` in namespace collection
- Redeploy monitoring stack to cluster
- Add Grafana dashboards:
  - Scan Job pod duration histogram
  - Resource usage by tier (small/medium/large)
  - Cache hit rates (from scanner metrics)
  - Scan throughput (jobs/hour)

### Phase 2.3: ArgoCD Setup
- `helm install argocd argo/argo-cd -n argocd --create-namespace`
- Create `k8s/argocd/` directory with Application CRDs:
  - `scanrook-app.yaml` — points to `k8s/scanrook/` in scanrook-ui repo
  - `monitoring-app.yaml` — points to `k8s/scanrook/monitoring/`
  - Future: db, storage namespace apps
- Configure auto-sync with pruning enabled
- Expose ArgoCD UI (optional: `argocd.apps.onetripp.com`)

### Phase 2.4: Longhorn UI
- Create ingress: `longhorn.apps.onetripp.com` → longhorn-frontend service
- Add Caddy block on edge-proxy, docker compose restart

### Phase 2.5: Hubble UI
- Create ingress: `hubble.apps.onetripp.com` → hubble-ui service
- Add Caddy block on edge-proxy, docker compose restart

---

## Milestone 3: Upload & Scan Control (Tab 2)

**Repo:** scanrook-ui (+ dispatcher cancel endpoint in rust-scanner-worker)

### Phase 3.1: Cancel Upload
- Add `AbortController` to presigned POST upload flow
- Cancel button in UploadCard during upload progress
- Cleanup: abort multipart upload on cancel

### Phase 3.2: Drag-and-Drop Upload
- Install `react-dropzone`
- Replace/augment file picker in `UploadCard` with drop zone
- Visual feedback: drag hover state, file type validation

### Phase 3.3: Multi-File Upload
- Support selecting/dropping multiple files
- Queue files, show per-file progress bars
- Create one `scan_job` per file
- Batch status summary

### Phase 3.4: Cancel/Stop/Start Scan
- **Dispatcher cancel endpoint**: Add HTTP endpoint to dispatcher that accepts job ID and deletes the K8s Job
- **API route**: `POST /api/jobs/[id]/cancel` — calls dispatcher cancel endpoint, updates job status to `cancelled`
- **Re-queue**: `POST /api/jobs/[id]/requeue` — resets failed job to `queued`
- **UI**: Cancel button on running jobs, retry button on failed jobs

### Phase 3.5: Light Summary Mode
- Add `summary_only` flag to scan job creation
- Scanner behavior: run full scan but API returns only severity counts
- Response format: `{ critical: 8000, high: 400, medium: 200, low: 50, heuristic: 150 }`
- Toggle on UploadCard: "Quick summary" checkbox

---

## Milestone 4: Scanner Quality (Tab 3)

**Repos:** rust_scanner, rust-scanner-worker

### Phase 4.1: SBOM Import Fix
- Debug `scanrook sbom import -f python_rprt.json --format json`
- Fix parsing/import logic

### Phase 4.2: Binary CPE False Positives
- Extend vendor lookup table
- Tighten confidence thresholds
- Reference: `rust_scanner/docs/plans/2026-03-05-binary-cpe-investigation.md`

### Phase 4.3: Heuristic Filter Bug
- Fix filtering showing findings when heuristic count is 0

### Phase 4.4: YARA Warning Cleanup
- Suppress "Running in light mode" on deep ISO scans where comps.xml filtering succeeds

### Phase 4.5: partial_failed Status
- Upgrade scan_status when comps filtering succeeds on deep ISO scans

### Phase 4.6: Preloaded YARA Definitions
- Bake YARA rules into scanner Docker image
- Update Dockerfile to include rule files

### Phase 4.7: Parallel Enrichment
- Run NVD, OSV, OVAL enrichment concurrently (tokio::join! or similar)
- Measure speedup

### Phase 4.8: Release v1.12.2
- Bump version, create git tag, push, create GitHub release with changelog

### Phase 4.9: Track Refactor Notes
- Document all speed/accuracy improvement opportunities observed during M4
- Write to `rust_scanner/docs/plans/2026-03-06-m7-refactor-notes.md`
- These notes define the scope of Milestone 7

---

## Milestone 5: Docker Registry Integration (Tab 3, after M4)

**Repos:** scanrook-ui, rust-scanner-worker

### Phase 5.1: OCI Registry Client
- Implement generic OCI distribution spec client in Go (worker repo)
- Support: token auth, manifest listing, layer download
- Works with Docker Hub, GHCR, any OCI-compliant registry

### Phase 5.2: Registry Browser UI
- New route: `/dashboard/registries`
- Browse repos and tags from configured registries
- Image metadata display (size, layers, created date)

### Phase 5.3: Scan from Registry
- "Scan" button on any image tag
- Worker pulls image layers, assembles tar, triggers scan job
- Progress shown same as file upload scans

### Phase 5.4: Org Registry Settings
- Per-org registry configuration page
- Fields: registry URL, username, token (encrypted in DB via Prisma)
- CRUD API: `POST/GET/PUT/DELETE /api/orgs/[id]/registries`

---

## Milestone 6: UI Polish & Admin (Tab 2, after M3)

**Repo:** scanrook-ui

### Phase 6.1: API Docs Fix
- Debug and fix OpenAPI/Swagger view rendering

### Phase 6.2: Docs Sidebar Scroll
- Add `overflow-y: auto` to docs sidebar component

### Phase 6.3: Blog Layout Fix
- Add left sidebar matching docs section layout
- Fix content layout/jumbling

### Phase 6.4: Admin Panel Tightening
- Audit existing `admin_override` role system
- Super admins: see all roles, move users between orgs
- Org admins: assign roles below their level only, cannot see higher roles
- Regular users: no role visibility
- Role hierarchy enforcement in API + UI

---

## Milestone 7: Aggressive Scanner Refactor (Tab 3, after M5)

**Repo:** rust_scanner

- Scope defined by `rust_scanner/docs/plans/2026-03-06-m7-refactor-notes.md` (written during M4)
- Focus areas: enrichment pipeline architecture, speed, accuracy
- Full refactor with breaking internal changes allowed
- Version bump to v1.13.0 + GitHub release

---

## Final Verification (Tab 4, after all milestones)

### Benchmark Suite
1. **End-to-end scan timing**: Upload small binary (~10MB), medium container (~500MB), large ISO (~2GB). Measure upload → report time for each.
2. **Accuracy baseline**: Record finding counts per severity per test file. This becomes the reference baseline.
3. **Load test**: 10+ concurrent file uploads. Measure:
   - Throughput (scans completed/hour)
   - Resource usage per node (CPU, memory via metrics-server)
   - Failure rate
   - Queue drain time
   - Tier enforcement under load
4. **Feature verification**: Walk through every feature from M2-M7:
   - ArgoCD sync working
   - Monitoring dashboards populated
   - Longhorn/Hubble UIs accessible
   - Drag-drop upload, multi-file, cancel upload, cancel scan, requeue
   - Light summary mode
   - Registry browser, scan from registry
   - API docs, blog, admin panel
5. **Report**: Written verification document with all results

---

## 4-Tab Execution Plan

| Tab | Milestones | Branch | Image Tags |
|-----|-----------|--------|------------|
| Tab 1 | M1 closeout → M2 | `feature/m2-infrastructure` (scanrook-ui) | `devintripp/deltaguard-ui:v2.0.0` |
| Tab 2 | M3 → M6 | `feature/m3-upload-control` then `feature/m6-ui-polish` (scanrook-ui) | `devintripp/deltaguard-ui:v2.1.0`, `v2.2.0` |
| Tab 3 | M4 → M5 → M7 | `fix/m4-scanner-quality` (scanner), `feature/m5-registry` (ui+worker), `feature/m7-refactor` (scanner) | scanner: `v1.12.2`, `v1.13.0`; worker: `devintripp/rust-scanner-worker:v2.0.0` |
| Tab 4 | Verification | No code changes | — |

### Sequencing
1. Tab 1 closes M1 first (merges branches) — signal to other tabs
2. Tabs 2 and 3 start immediately after M1 merge
3. Tab 4 waits for Tabs 1-3 to all complete
4. Final report delivered to user

