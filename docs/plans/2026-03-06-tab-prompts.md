# ScanRook 4-Tab Parallel Execution Prompts

**Date:** 2026-03-06
**Usage:** Open 4 Claude Code terminals. Paste one prompt per tab. All tabs run autonomously.

**IMPORTANT:** Start Tab 1 first. Tabs 2-4 can start immediately — Tab 1 will close out M1, then Tabs 2 and 3 will begin their feature work after M1 merges. Tab 4 waits for all others.

**Launch command for all tabs:**
```bash
cd ~/Desktop/GitHub/scanrook && claude --add-dir ~/Desktop/GitHub/scanrook/rust-scanner-worker --add-dir ~/Desktop/GitHub/scanrook/scanrook-ui --add-dir ~/Desktop/GitHub/scanrook/rust_scanner
```

---

## TAB 1 — Milestone 1 Closeout + Milestone 2 Infrastructure

```
You are executing a fully autonomous plan. Do NOT ask me questions — all decisions have been made. Pause ONLY for handoff when all work in this tab is complete.

CRITICAL RULES:
- Never add Co-Authored-By or Claude credit to commits
- Use Bash for file creation/editing (cat/sed), not the Write tool
- Docker builds: ALWAYS use --platform linux/amd64
- Cluster access: SSH to dg-node1 (via dg-bastion). kubeconfig is on the nodes.
- Edge-proxy Caddy: SSH to edge-proxy, edit /opt/edge-proxy/Caddyfile, then run `docker compose restart` to reload
- The K8s namespace is `scanrook`, NOT `deltaguard`
- Branch naming: feature/<short-description> or fix/<short-description>

REPOS:
- Scanner worker: ~/Desktop/GitHub/scanrook/rust-scanner-worker (currently on feature/k8s-job-scheduler)
- UI: ~/Desktop/GitHub/scanrook/scanrook-ui (currently on feature/k8s-job-scheduler) 
- Scanner: ~/Desktop/GitHub/scanrook/rust_scanner (on main)

## MILESTONE 1 CLOSEOUT

### Task 20: Concurrent Scan Verification
- SSH to a cluster node and verify the dispatcher is running: `kubectl -n scanrook get pods`
- Check if there are any existing queued/running scan jobs: `kubectl -n scanrook get jobs`
- Verify that the tier system works by checking the dispatcher logs and the scanrook-scheduler-config ConfigMap
- If you can trigger scans programmatically (via API or direct DB insert), test 3+ concurrent small-tier scans
- If you cannot trigger scans (no test files available), verify the code logic in the dispatcher handles concurrency correctly by code review, and verify the ConfigMap tier limits are correctly configured on the cluster
- Document findings

### Task 21: Old Worker Cleanup + Merge
- Delete the scanrook-worker deployment (0 replicas): `kubectl -n scanrook delete deployment scanrook-worker`
- Remove worker-deployment.yaml from k8s manifests in scanrook-ui repo
- In rust-scanner-worker repo: merge feature/k8s-job-scheduler → main (git checkout main && git merge feature/k8s-job-scheduler)
- In scanrook-ui repo: merge feature/k8s-job-scheduler → main (git checkout main && git merge feature/k8s-job-scheduler)
- Push both main branches to origin
- Verify merges are clean

## MILESTONE 2: INFRASTRUCTURE & OBSERVABILITY

Work on branch: feature/m2-infrastructure (in scanrook-ui repo)

### Phase 2.1: Directory Rename
- Rename k8s/deltaguard/ → k8s/scanrook/
- Update all internal references in kustomization.yaml and any scripts
- Commit: "chore: rename k8s/deltaguard to k8s/scanrook"

### Phase 2.2: Monitoring Fix
- In k8s/scanrook/monitoring/prometheus-config.yaml: change all `deltaguard` → `scanrook` namespace references
- In k8s/scanrook/monitoring/promtail-daemonset.yaml: change `deltaguard` → `scanrook` in namespace collection config
- Apply updated monitoring manifests to cluster via SSH
- Create Grafana dashboards (JSON provisioning):
  - Scan Job pod duration histogram
  - Resource usage by tier (small/medium/large) 
  - Scan throughput (jobs/hour)
  - Cache hit rate panel
- Add dashboard JSON to k8s/scanrook/monitoring/grafana-dashboards/ ConfigMap
- Commit: "fix: update monitoring namespace refs and add scan dashboards"

### Phase 2.3: ArgoCD Setup
- SSH to cluster node, install ArgoCD via Helm:
  ```
  helm repo add argo https://argoproj.github.io/argo-helm
  helm install argocd argo/argo-cd -n argocd --create-namespace
  ```
- Create k8s/argocd/ directory in scanrook-ui repo
- Create ArgoCD Application CRDs:
  - scanrook-app.yaml: points to k8s/scanrook/ dir, auto-sync with pruning
  - monitoring-app.yaml: points to k8s/scanrook/monitoring/
- Apply Application CRDs to cluster
- Optionally expose ArgoCD UI at argocd.apps.onetripp.com (Caddy + ingress)
- Commit: "feat: add ArgoCD with Application CRDs for scanrook and monitoring"

### Phase 2.4: Longhorn UI
- SSH to cluster, find longhorn-frontend service: `kubectl -n longhorn-system get svc`
- Create ingress for longhorn.apps.onetripp.com → longhorn-frontend service
- SSH to edge-proxy, add Caddy block:
  ```
  longhorn.apps.onetripp.com {
    reverse_proxy 192.168.1.80:30080
  }
  ```
  Then: `docker compose restart`
- Commit: "feat: expose Longhorn UI at longhorn.apps.onetripp.com"

### Phase 2.5: Hubble UI  
- SSH to cluster, find hubble-ui service: `kubectl -n kube-system get svc | grep hubble`
- Create ingress for hubble.apps.onetripp.com → hubble-ui service
- SSH to edge-proxy, add Caddy block and docker compose restart
- Commit: "feat: expose Hubble UI at hubble.apps.onetripp.com"

### Finalize
- Merge feature/m2-infrastructure → main in scanrook-ui
- Push to origin
- Build and push UI image: docker build --platform linux/amd64 -t devintripp/deltaguard-ui:v2.0.0 . && docker push devintripp/deltaguard-ui:v2.0.0
- Update deployment on cluster to use new image tag
- Verify all UIs are accessible

HANDOFF: When complete, write a summary to ~/Desktop/GitHub/scanrook/docs/plans/tab1-complete.md with what was done, any issues, and the final state.
```

---

## TAB 2 — Milestone 3 (Upload & Scan Control) + Milestone 6 (UI Polish)

```
You are executing a fully autonomous plan. Do NOT ask me questions — all decisions have been made. Pause ONLY for handoff when all work in this tab is complete.

CRITICAL RULES:
- Never add Co-Authored-By or Claude credit to commits
- Use Bash for file creation/editing (cat/sed), not the Write tool
- Docker builds: ALWAYS use --platform linux/amd64
- Cluster access: SSH to dg-node1 (via dg-bastion)
- The K8s namespace is `scanrook`, NOT `deltaguard`
- Branch naming: feature/<short-description>

REPOS:
- UI: ~/Desktop/GitHub/scanrook/scanrook-ui
- Worker (for cancel endpoint only): ~/Desktop/GitHub/scanrook/rust-scanner-worker

PREREQUISITE: Before starting feature work, check that feature/k8s-job-scheduler has been merged to main in both repos. If not merged yet, wait and check again every 2 minutes. Once merged, pull main and create your feature branch from it.

## MILESTONE 3: UPLOAD & SCAN CONTROL

Work on branch: feature/m3-upload-control (in scanrook-ui)
Also: feature/m3-cancel-api (in rust-scanner-worker) for the dispatcher cancel endpoint

### Phase 3.1: Cancel Upload
- Find the upload logic in scanrook-ui (likely in src/components/ near UploadCard)
- Add AbortController to the presigned POST upload
- Add a Cancel button that appears during upload progress
- On cancel: abort the fetch, clean up UI state
- Commit: "feat: add cancel button for in-progress uploads"

### Phase 3.2: Drag-and-Drop Upload
- Install react-dropzone: npm install react-dropzone
- Modify UploadCard to use react-dropzone as the primary upload interface
- Add visual feedback: drag hover border, accepted/rejected file indicators
- Keep the existing file picker as a fallback (click to browse)
- Commit: "feat: add drag-and-drop file upload with react-dropzone"

### Phase 3.3: Multi-File Upload
- Extend UploadCard to accept multiple files
- Show per-file progress bars in a list
- Create one scan_job per file (call POST /api/jobs for each)
- Add batch status summary (e.g., "3/5 uploads complete")
- Commit: "feat: support multi-file upload with per-file progress"

### Phase 3.4: Cancel/Stop/Start Scan
- IN RUST-SCANNER-WORKER (on feature/m3-cancel-api branch):
  - Add HTTP cancel endpoint to the dispatcher: DELETE /jobs/{id} or POST /jobs/{id}/cancel
  - Endpoint should: delete the K8s Job (if running), update job status in DB to "cancelled"
  - Commit in worker repo: "feat: add cancel scan endpoint to dispatcher"
  - Merge to main, push
  - Build and push new worker image with semver tag
  - Deploy to cluster
- IN SCANROOK-UI:
  - Add API route: POST /api/jobs/[id]/cancel — proxies to dispatcher cancel endpoint
  - Add API route: POST /api/jobs/[id]/requeue — resets failed/cancelled job to queued
  - Add Cancel button on running job detail pages
  - Add Retry button on failed/cancelled job detail pages
  - Commit: "feat: add cancel and requeue scan controls"

### Phase 3.5: Light Summary Mode
- This is a UI-only feature — the scan runs normally
- Add "Quick Summary" checkbox to UploadCard
- When enabled, the job detail page shows ONLY severity counts:
  - Critical: X, High: Y, Medium: Z, Low: W, Heuristic: H
- The full report is still available behind a "View Full Report" link
- Store the summary_only preference in the scan_job record
- Commit: "feat: add light summary mode showing severity counts only"

### Finalize M3
- Merge feature/m3-upload-control → main in scanrook-ui
- Push to origin

## MILESTONE 6: UI POLISH & ADMIN

Work on branch: feature/m6-ui-polish (in scanrook-ui, from main after M3 merge)

### Phase 6.1: API Docs Fix
- Find the API docs / Swagger page (likely /api-docs or similar route)
- Debug what's broken in the rendering
- Fix it
- Commit: "fix: repair API docs / OpenAPI view"

### Phase 6.2: Docs Sidebar Scroll
- Find the docs sidebar component
- Add overflow-y: auto (or overflow-y: scroll) with appropriate max-height
- Commit: "fix: make docs sidebar scrollable"

### Phase 6.3: Blog Layout Fix
- Find the blog layout
- Add left sidebar matching the docs section layout
- Fix content jumbling/layout issues
- Commit: "fix: add sidebar and fix blog layout"

### Phase 6.4: Admin Panel Tightening
- Find the existing admin_override role system (check master admin / org pages)
- Implement role hierarchy visibility:
  - Super admin (admin_override): sees all roles, can move users between orgs
  - Org admin: can assign roles below their level only, cannot see roles above theirs
  - Regular users: no role management visibility at all
- Enforce this in BOTH the API routes AND the UI components
- Commit: "feat: enforce role hierarchy visibility in admin panel"

### Finalize M6
- Merge feature/m6-ui-polish → main
- Push to origin
- Build and push final UI image: docker build --platform linux/amd64 -t devintripp/deltaguard-ui:v2.2.0 . && docker push
- Deploy to cluster

HANDOFF: When complete, write a summary to ~/Desktop/GitHub/scanrook/docs/plans/tab2-complete.md with what was done, any issues, and the final state.
```

---

## TAB 3 — Milestone 4 (Scanner Quality) + Milestone 5 (Registry) + Milestone 7 (Refactor)

```
You are executing a fully autonomous plan. Do NOT ask me questions — all decisions have been made. Pause ONLY for handoff when all work in this tab is complete.

CRITICAL RULES:
- Never add Co-Authored-By or Claude credit to commits
- Use Bash for file creation/editing (cat/sed), not the Write tool  
- Docker builds: ALWAYS use --platform linux/amd64
- Cluster access: SSH to dg-node1 (via dg-bastion)
- Branch naming: fix/<short-description> for bug fixes, feature/<short-description> for features

REPOS:
- Scanner: ~/Desktop/GitHub/scanrook/rust_scanner
- Worker: ~/Desktop/GitHub/scanrook/rust-scanner-worker
- UI: ~/Desktop/GitHub/scanrook/scanrook-ui (for M5 registry UI)

PREREQUISITE: Before starting, check that feature/k8s-job-scheduler has been merged to main in rust-scanner-worker. If not merged yet, wait and check again every 2 minutes. Once merged, pull main and create your feature branch from it.

## MILESTONE 4: SCANNER QUALITY

Work on branch: fix/m4-scanner-quality (in rust_scanner)

### Phase 4.1: SBOM Import Fix
- Find the SBOM import code (likely src/main.rs sbom subcommand or a dedicated module)
- Test: `cargo run -- sbom import -f <test_file> --format json`
- Debug why it fails with "failed to import SBOM"
- Fix the parsing/import logic
- Add or fix tests
- Commit: "fix: SBOM JSON import parsing"

### Phase 4.2: Binary CPE False Positives
- Read the investigation doc: docs/plans/2026-03-05-binary-cpe-investigation.md
- Find the vendor lookup table (added in v1.12.0)
- Extend the table with more accurate vendor mappings
- Tighten confidence thresholds to reduce false positives
- Commit: "fix: reduce binary CPE false positives with expanded vendor table"

### Phase 4.3: Heuristic Filter Bug
- Find where heuristic findings are filtered in the report/findings code
- Fix: when heuristic count is 0, filter should return empty results
- Commit: "fix: heuristic filter returns empty when count is 0"

### Phase 4.4: YARA Warning Cleanup
- Find the "Running in light mode" warning message
- Suppress it when running deep mode ISO scans where comps.xml filtering is active
- Commit: "fix: suppress misleading light mode warning on deep ISO scans"

### Phase 4.5: partial_failed Status
- Find where scan_status is set during ISO scans
- When comps.xml filtering succeeds on deep ISO scans, status should not be partial_failed
- Commit: "fix: correct scan status when comps filtering succeeds"

### Phase 4.6: Preloaded YARA Definitions
- Find or create a yara-rules/ directory in the scanner repo
- Add standard YARA rule files
- Update the Dockerfile to COPY rules into the image
- Update scanner to load rules from the baked-in path
- Commit: "feat: preload YARA definitions into scanner image"

### Phase 4.7: Parallel Enrichment
- Find the enrichment pipeline (likely sequential calls to NVD, OSV, OVAL in vuln.rs or similar)
- Refactor to run enrichment sources concurrently using tokio::join! or similar
- Measure speedup (note before/after times in commit message)
- Commit: "feat: run NVD/OSV/OVAL enrichment concurrently"

### Phase 4.8: Release v1.12.2
- Update version in Cargo.toml to 1.12.2
- Update any version strings in the code
- git tag v1.12.2
- git push origin main --tags
- Create GitHub release: gh release create v1.12.2 --title "v1.12.2" --notes "Bug fixes: SBOM import, CPE false positives, heuristic filter, YARA warnings, parallel enrichment"
- Commit: "chore: bump version to v1.12.2"

### Phase 4.9: Track Refactor Notes
- Create docs/plans/2026-03-06-m7-refactor-notes.md
- Document EVERY speed/accuracy improvement opportunity you noticed during M4:
  - Enrichment pipeline architecture issues
  - Cache inefficiencies
  - Parsing bottlenecks
  - Data structure improvements
  - Any code smells or tech debt
- This file defines the scope of Milestone 7
- Commit: "docs: add M7 refactor notes from M4 observations"

### Finalize M4
- Merge fix/m4-scanner-quality → main in rust_scanner
- Push to origin

## MILESTONE 5: DOCKER REGISTRY INTEGRATION

Work on branches:
- feature/m5-registry-client (in rust-scanner-worker)
- feature/m5-registry-ui (in scanrook-ui)

### Phase 5.1: OCI Registry Client (Go — worker repo)
- Create internal/registry/ package
- Implement OCI Distribution Spec client:
  - Token authentication (Bearer token flow)
  - GET /v2/{name}/tags/list — list tags
  - GET /v2/{name}/manifests/{reference} — get manifest
  - GET /v2/{name}/blobs/{digest} — download layer
- Support Docker Hub, GHCR, and any OCI-compliant registry
- The client reads credentials from the database (passed by the dispatcher)
- Commit: "feat: add generic OCI registry client"

### Phase 5.2: Registry API Endpoints (Go — worker repo)
- Add HTTP endpoints to the dispatcher for registry operations:
  - GET /registries/{id}/repos — list repositories
  - GET /registries/{id}/repos/{name}/tags — list tags
  - POST /registries/{id}/repos/{name}/tags/{tag}/scan — trigger scan from registry
- For scan: pull manifest, download layers, assemble tar, create scan job
- Commit: "feat: add registry API endpoints to dispatcher"

### Phase 5.3: Registry Browser UI (scanrook-ui)
- Add Prisma model for org registries (url, name, encrypted credentials)
- Add API routes:
  - POST/GET/PUT/DELETE /api/orgs/[orgId]/registries — CRUD
  - GET /api/registries/[id]/repos — proxy to dispatcher
  - GET /api/registries/[id]/repos/[name]/tags — proxy to dispatcher
  - POST /api/registries/[id]/repos/[name]/tags/[tag]/scan — proxy to dispatcher
- New pages:
  - /dashboard/registries — list configured registries, browse repos/tags
  - /dashboard/registries/[id] — browse specific registry
- Org settings page: add registry management section
- Commit: "feat: add registry browser UI and org settings"

### Phase 5.4: Finalize M5
- Merge feature branches to main in both repos
- Build and push worker image with new semver tag
- Build and push UI image
- Deploy to cluster
- Verify registry browsing works end-to-end

## MILESTONE 7: AGGRESSIVE SCANNER REFACTOR

Work on branch: feature/m7-scanner-refactor (in rust_scanner)

- Read docs/plans/2026-03-06-m7-refactor-notes.md for the full scope
- Execute each item documented during M4
- Focus on speed and accuracy improvements
- This is a full refactor — breaking internal changes are allowed
- Bump version to v1.13.0
- Create GitHub release
- Build updated scanner into worker Docker image
- Deploy to cluster

HANDOFF: When complete, write a summary to ~/Desktop/GitHub/scanrook/docs/plans/tab3-complete.md with what was done, any issues, and the final state.
```

---

## TAB 4 — Final Verification & Benchmarks

```
You are executing final verification and benchmarking for the ScanRook platform. Do NOT start until Tabs 1-3 are all complete.

CRITICAL RULES:
- Never add Co-Authored-By or Claude credit to commits
- Cluster access: SSH to dg-node1 (via dg-bastion)
- The K8s namespace is `scanrook`

CHECK FOR COMPLETION: Before starting, verify these files exist:
- ~/Desktop/GitHub/scanrook/docs/plans/tab1-complete.md
- ~/Desktop/GitHub/scanrook/docs/plans/tab2-complete.md
- ~/Desktop/GitHub/scanrook/docs/plans/tab3-complete.md

If any are missing, wait 5 minutes and check again. Repeat until all exist.

REPOS:
- UI: ~/Desktop/GitHub/scanrook/scanrook-ui
- Worker: ~/Desktop/GitHub/scanrook/rust-scanner-worker
- Scanner: ~/Desktop/GitHub/scanrook/rust_scanner

## PHASE 1: SMOKE TEST

Verify every service is running:
- SSH to cluster node
- kubectl -n scanrook get pods (web, dispatcher, redis all running)
- kubectl -n monitoring get pods (grafana, prometheus, loki, promtail all running)
- kubectl -n argocd get pods (argocd server running)
- Verify all UIs are accessible:
  - scanrook.io / scanrook.sh (web app)
  - grafana.scanrook.io (Grafana)
  - longhorn.apps.onetripp.com (Longhorn)
  - hubble.apps.onetripp.com (Hubble)
  - argocd.apps.onetripp.com (ArgoCD, if exposed)

## PHASE 2: FEATURE VERIFICATION

Test every feature from milestones 2-7:

### M2 Features
- [ ] ArgoCD is syncing scanrook namespace from git
- [ ] Grafana dashboards show scan metrics
- [ ] Prometheus is scraping scanrook namespace pods
- [ ] Promtail is collecting logs from scanrook namespace
- [ ] Longhorn UI accessible at longhorn.apps.onetripp.com
- [ ] Hubble UI accessible at hubble.apps.onetripp.com

### M3 Features
- [ ] Upload a file via drag-and-drop
- [ ] Upload multiple files at once, verify per-file progress
- [ ] Start an upload, then cancel it mid-progress
- [ ] Start a scan, then cancel it (verify K8s Job is deleted)
- [ ] Requeue a failed/cancelled scan
- [ ] Toggle "Quick Summary" mode, verify only severity counts shown

### M4 Features
- [ ] Scanner version is v1.12.2
- [ ] Run a binary scan, verify fewer CPE false positives than before
- [ ] Run a deep ISO scan, verify no "Running in light mode" warning
- [ ] Verify heuristic filter returns empty when count is 0

### M5 Features
- [ ] Configure a Docker Hub registry in org settings
- [ ] Browse repos and tags from the registry browser
- [ ] Trigger a scan from a registry image
- [ ] Verify scan completes and shows results

### M6 Features
- [ ] API docs page renders correctly
- [ ] Docs sidebar is scrollable
- [ ] Blog layout has left sidebar, content not jumbled
- [ ] Admin panel: super admin sees all roles
- [ ] Admin panel: org admin only sees lower roles
- [ ] Admin panel: regular user sees no role management

### M7 Features
- [ ] Scanner version is v1.13.0
- [ ] Enrichment pipeline runs faster than v1.12.2
- [ ] Scan accuracy maintained or improved

## PHASE 3: END-TO-END SCAN BENCHMARK

For each test file type, measure upload → report completion time:

1. **Small binary** (~10MB): find or create a test binary
   - Upload via UI
   - Record: upload time, scan time, total time, finding count per severity

2. **Medium container** (~500MB): use a known Docker image tar
   - Upload via UI
   - Record: upload time, scan time, total time, finding count per severity

3. **Large ISO** (~2GB): use a known ISO if available, or the largest available test file
   - Upload via UI
   - Record: upload time, scan time, total time, finding count per severity

## PHASE 4: LOAD TEST

1. Upload 10+ files concurrently (mix of sizes)
2. Monitor cluster resources via SSH: `kubectl top nodes`, `kubectl top pods -n scanrook`
3. Record:
   - Total throughput (scans completed per hour)
   - Peak CPU/memory per node
   - Peak CPU/memory per scan pod (by tier)
   - Number of failed scans
   - Queue drain time (time from last upload to last scan completion)
   - Tier enforcement: verify small/medium/large concurrency limits hold
4. Check for:
   - OOMKills: `kubectl -n scanrook get events --field-selector reason=OOMKilling`
   - Pod evictions
   - Node pressure

## PHASE 5: WRITE VERIFICATION REPORT

Create ~/Desktop/GitHub/scanrook/docs/plans/2026-03-06-final-verification-report.md with:

1. **Executive Summary**: Overall pass/fail, key metrics
2. **Service Health**: All pods, all UIs, ArgoCD sync status
3. **Feature Matrix**: Checklist from Phase 2 with pass/fail for each
4. **Benchmark Results**:
   - Table: file type, size, upload time, scan time, total time, findings
   - Comparison to pre-milestone baseline (108s from M1)
5. **Load Test Results**:
   - Throughput, resource usage, failure rate
   - Tier enforcement verification
6. **Issues Found**: Any bugs, regressions, or concerns
7. **Recommendations**: Next steps, tuning suggestions

Commit the report to the scanrook repo.

HANDOFF: Present the verification report to the user. This is the final deliverable.
```

