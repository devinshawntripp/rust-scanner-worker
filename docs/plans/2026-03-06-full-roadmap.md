# ScanRook Full Roadmap

**Date:** 2026-03-06
**Status:** Approved

---

## Milestone 1: K8s-Native Scan Scheduler — 95% DONE

**Goal:** Replace in-process scan execution with K8s Jobs per scan, with resource-aware scheduling.

**Status:** 19/21 tasks complete. Scans working end-to-end (108s, 99.98% cache hit rate, 18K findings).

**Remaining:**
- Task 20: Verify resource isolation with concurrent scans
- Task 21: Remove old worker deployment and clean up manifests

**Session fixes (2026-03-06):**
- DNS poisoning fix (dnsPolicy: None on scan pods)
- Architecture mismatch fix (--platform linux/amd64)
- Cache DB env fix (SCANROOK_ENRICHMENT_DATABASE_URL)
- Ping timeout increase (2s → 10s)
- Scanner timeout increase (1800s → 3600s)

**Design:** `2026-03-06-k8s-native-scan-scheduler-design.md`
**Plan:** `2026-03-06-k8s-native-scan-scheduler-plan.md`

---

## Milestone 2: Infrastructure & Observability

**Goal:** GitOps-managed cluster with full observability and exposed storage/network UIs.

### Phase 1: ArgoCD Setup
- Install ArgoCD on the cluster
- Migrate all K8s manifests to ArgoCD Applications (scanrook-web, dispatcher, redis, RBAC, quotas, network policies)
- Set up auto-sync from git repos

### Phase 2: Monitoring Fixes
- Fix Grafana dashboards (was CrashLoopBackOff, may still need dashboard setup)
- Fix Promtail (0/1 ready on all nodes)
- Create scan Job dashboards: pod duration, resource usage by tier, cache hit rates, scan throughput

### Phase 3: Longhorn UI
- Expose Longhorn dashboard at `longhorn.apps.onetripp.com`
- Add ingress route + Caddy reverse proxy block
- There is already a running pod in the longhorn-system namespace

### Phase 4: Hubble UI
- Expose Hubble UI for Cilium network observability
- Add ingress route + Caddy reverse proxy block

---

## Milestone 3: Upload & Scan Control

**Goal:** Full upload lifecycle control and scan management from the UI.

### Items
- **Cancel an upload** — abort in-progress S3 presigned POST uploads
- **Drag-and-drop upload** — replace or augment the file picker with drop zone
- **Multi-file uploads** — upload and queue multiple files in one action
- **Cancel/stop/start a scan** — UI controls to cancel running scans, re-queue failed ones
- **Light summary option** — quick summary view without full enrichment details

---

## Milestone 4: Scanner Quality

**Goal:** Fix scanner bugs and improve scan accuracy and performance.

### Bug Fixes
- **SBOM import fix** — `scanrook sbom import -f python_rprt.json --format json` fails with "failed to import SBOM"
- **Binary CPE false positives (BUG-8)** — vendor lookup table in v1.12.0 partially addressed, more work needed. Investigation doc: `rust_scanner/docs/plans/2026-03-05-binary-cpe-investigation.md`
- **Heuristic filter bug** — filtering on "heuristic" shows findings even when count is 0
- **YARA warning cleanup** — deep mode ISO scans show misleading "Running in light mode" when comps.xml filtering works fine
- **partial_failed status** — upgrade scan_status when comps filtering succeeds on deep ISO scans

### Enhancements
- **Preloaded YARA definitions** — bake YARA rules into the scanner image
- **Parallel enrichment pipeline** — NVD, OSV, and other enrichment sources should run concurrently where possible instead of linear pipeline

---

## Milestone 5: Docker Registry Integration

**Goal:** Browse and scan Docker images directly from the UI without manual file upload.

### Items
- **Docker registry browser** — browse containers/tags in a connected registry from the UI
- **Scan from registry** — select an image and trigger a scan directly
- **Org settings for registry** — configure docker repo or sub-repo per organization

---

## Milestone 6: UI Polish & Admin

**Goal:** Fix broken UI views and add admin management features.

### Bug Fixes
- **API docs broken** — the OpenAPI/Swagger view is messed up
- **Docs sidebar not scrollable** — sidebar needs overflow scroll
- **Blog layout broken** — content jumbled, needs left sidebar like docs section

### Admin Features
- **Master admin panel** — ability to move users between orgs as admin_override

---

## Priority Order

1. **Milestone 1** — Close out (2 tasks remaining)
2. **Milestone 2** — Infrastructure & Observability (ArgoCD, monitoring, Longhorn, Hubble)
3. **Milestone 3** — Upload & Scan Control
4. **Milestone 4** — Scanner Quality
5. **Milestone 5** — Docker Registry Integration
6. **Milestone 6** — UI Polish & Admin

Milestones 3-6 can be reordered based on user priorities. Milestones 4 and 6 contain independent bug fixes that can be cherry-picked into earlier milestones if needed.
