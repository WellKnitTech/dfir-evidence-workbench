# DFIR Evidence Workbench
# Security, Isolation, and Defensibility Requirements

Status: implementation baseline and release gate
Scope: tenants, cases, evidence, derived artifacts, API/control plane, data-plane workers, rootless Podman runtime, scanners/parsers, network egress, integrations, and audit evidence.

Normative language: SHALL/MUST is mandatory. SHOULD is recommended unless a documented, approved exception exists. All controls are deny-by-default and fail closed when a decision is unavailable or indeterminate.

## 1. Security objectives and trust boundaries

1. Evidence is sensitive and untrusted. Original bytes are preserved, hashed, and never executed or modified by analysis.
2. Tenant and case are independent authorization boundaries. A valid tenant membership does not authorize access to every case.
3. The control plane manages identity, authorization, policy, orchestration, metadata, and audit. The data plane stores/processes evidence and derivatives. Neither receives authority outside its declared role.
4. Every object, queue message, job, callback, temporary root, and audit event carries immutable tenant and case scope where applicable.
5. A release is not accepted on the basis of unit tests alone: deployed boundaries, runtime configuration, adversarial fixtures, telemetry, and manual review are required.

Trust boundaries:
- Client/analyst -> authenticated API and UI
- Control plane -> storage, queue, integrations, and policy services
- Data-plane worker -> read-only evidence and private writable scratch
- Scanner/parser sandbox -> untrusted bytes and disposable outputs
- Workbench -> controlled DNS/proxy/firewall boundary
- Application -> append-only, tamper-evident audit sink

## 2. Tenant, case, and evidence isolation

REQ-ISO-001 — The platform SHALL isolate each tenant's metadata, evidence references, object-storage namespace, derived artifacts, reports, credentials, jobs, and audit records from every other tenant.

REQ-ISO-002 — The platform SHALL isolate evidence, extracted files, timelines, indicators, notes, reports, task state, and integrations between cases, including cases in one tenant.

REQ-ISO-003 — Every scoped object and asynchronous operation SHALL contain immutable tenant/case identifiers. Services SHALL authorize the complete scope before persistence, reads, writes, downloads, exports, queue consumption, callbacks, or side effects. Missing, altered, mismatched, expired, or replayed scope SHALL be rejected.

REQ-ISO-004 — Storage paths, volume names, database rows, object prefixes, temporary roots, and queue topics SHALL use server-generated collision-resistant identifiers. User names are metadata only and SHALL never select a filesystem path or authorization scope.

REQ-ISO-005 — Original evidence SHALL reside in a read-only or write-once boundary. Workers SHALL use verified working copies or controlled read-only mounts. No service may mount original evidence read-write.

REQ-ISO-006 — Temporary, cache, intermediate, and derived data SHALL remain in the owning case/tenant boundary, have restrictive permissions, follow retention policy, and be cleaned idempotently without following links outside the root.

REQ-AUTH-001 — Control-plane, data-plane, API, UI, queue, integration, and container access SHALL deny by default. Policy-store, identity, scope-resolution, storage-authorization, or runtime-policy failure SHALL deny or safely pause the affected operation.

REQ-AUTH-002 — Permissions SHALL be action-specific (for example case-read, evidence-read, evidence-export, artifact-write, report-approve, integration-admin, and tenant-admin). Roles SHALL grant the minimum required set and SHALL not imply export, deletion, policy, or credential administration.

REQ-AUTH-003 — Authorization SHALL be server-side on every request and asynchronous operation, using verified principal, action, resource, tenant/case scope, and current policy. Client-supplied IDs, role fields, filters, hidden UI state, and claims not independently validated SHALL not authorize access.

REQ-AUTH-004 — Evidence export, deletion, retention override, case closure, credential changes, and policy administration SHALL require explicit high-impact permissions. Dual control, where configured, SHALL use a distinct approving principal; self-approval and expired emergency grants SHALL fail.

REQ-ARCH-001 — Data-plane workers SHALL not administer identity, policy, host, or container runtime state. Control-plane services SHALL not receive unrestricted evidence mounts. Service communication, queue messages, callbacks, and integrations SHALL be identity-authenticated, scope-carrying, allowlisted, and re-authorized at consumption time.

## 3. Rootless Podman and runtime least privilege

REQ-POD-001 — Production containers SHALL run rootless under a dedicated non-root host account. Host-root UID mapping and rootful Podman SHALL be prohibited unless an approved exception identifies purpose, scope, duration, owner, and compensating controls.

REQ-POD-002 — Each container SHALL use reviewed subordinate UID/GID mappings. Shared volumes SHALL be ownership- and label-compatible with those mappings; peer-case and host-owned data SHALL be inaccessible.

REQ-POD-003 — Containers SHALL not use privileged mode, host PID/IPC/UTS/network namespaces, broad host mounts, host devices, runtime sockets, or broad filesystem access. Exceptions SHALL be narrow and testable.

REQ-POD-004 — Container roots SHALL be read-only where feasible. Writable paths SHALL be explicit, private, case-scoped temporary or memory-backed volumes; they SHALL not include image layers, host root, originals, or unrelated cases.

REQ-POD-005 — All Linux capabilities SHALL be dropped by default. High-risk capabilities such as CAP_SYS_ADMIN, CAP_SYS_PTRACE, and CAP_NET_ADMIN require explicit review and SHALL otherwise be absent. `no-new-privileges`, restrictive seccomp, and minimal service accounts are required.

REQ-POD-006 — CPU, memory, PID/process, file-descriptor, and temporary-storage limits SHALL be explicit. Exceeding a limit or attempting a blocked syscall SHALL fail safely, emit an audit event, and not impair another tenant.

REQ-POD-007 — Images SHALL be approved, vulnerability/secret scanned, and pinned by immutable digest before admission. Configuration and policy linting SHALL reject prohibited privileges, writable evidence mounts, host networking, missing limits, or missing scope labels.

## 4. Upload, path, archive, and parser defenses

REQ-UPL-001 — Uploads SHALL be streamed into quarantine with enforced request, per-file, count, concurrency, and case-byte limits. Declared and observed sizes SHALL be checked; false Content-Length, alternate endpoints, multipart boundaries, retries, and races SHALL not bypass limits. Rejected partial files SHALL be removed.

Baseline ordinary limits: 5 GiB request/file, 100 files/request, 10,000 files/case, plus deployment-defined aggregate quota with headroom. Large forensic images require a separate equivalently controlled profile.

REQ-UPL-002 — Admission SHALL validate normalized extension, declared MIME, magic bytes/content identification, structure, and policy using a deny-by-default allowlist. Accepted storage does not imply safe preview or parsing.

REQ-UPL-003 — The quarantine write SHALL calculate SHA-256 and preserve original bytes. Promotion requires validation and records hash, size, detected type, uploader, case, timestamps, and validation state.

REQ-PATH-001 — Client filenames SHALL be metadata only. Strip controls, NUL, CR/LF, bidirectional overrides, and unsafe whitespace; normalize Unicode (NFC); bound UTF-8 length; and preserve the original only in an access-controlled escaped audit field.

REQ-PATH-002 — Reject absolute, UNC, drive-qualified, traversal, dot-segment, mixed-separator, NUL, malformed-encoding, ADS, device-name, and reserved-name forms both before and after canonical normalization.

REQ-PATH-003 — Extraction SHALL use a fresh private per-job root. Resolve canonical containment at creation time without following untrusted links; reject symlinks, hardlinks, junctions, reparse points, devices, FIFOs, sockets, overwrites, duplicate/colliding normalized paths, and link races. Use O_NOFOLLOW/openat or an equivalent safe primitive.

REQ-ARC-001 — Before and during extraction enforce maximum entries, compressed input, per-entry expanded bytes, total expanded bytes, nesting depth, compression ratio, CPU, process/thread count, and wall-clock time. Baselines are 100,000 entries, 20 GiB total, 5 GiB per entry, 100:1 ratio, depth 2, and 10-minute archive timeout, subject to deployment profile.

REQ-ARC-002 — Observed byte counts, not archive headers alone, SHALL govern limits. Forged sizes, malformed indexes, unsupported/encrypted/multi-volume/self-extracting archives, parser warnings, and unsafe features SHALL produce quarantined/rejected status; no shell fallback is permitted.

REQ-ARC-003 — Nested/disguised archives SHALL be detected by content, charged against parent budgets, and processed only to the configured depth. Beyond-limit content remains an unprocessed artifact with an explicit status. Timeout SHALL kill the full parser process group and remove partial output.

## 5. Secrets and API authorization

REQ-SEC-001 — Production secrets SHALL not appear in source, images, build contexts, manifests, arguments, process titles, environment dumps, logs, traces, metrics, crash output, URLs, evidence, or reports. CI/admission scanning SHALL fail on detected secrets and trigger rotation where exposure is possible.

REQ-SEC-002 — Secrets SHALL be held in an approved vault/secret manager with versioning, access policy, audit events, encryption at rest, and per-service identity. Services retrieve only named versions they need and cannot enumerate the vault. Development/test/production namespaces are separate.

REQ-SEC-003 — Secret use SHALL be least privilege, short-lived where possible, revocable, owner- and expiry-documented, and rotation-capable with overlapping versions. Redaction SHALL cover authorization headers, cookies, private keys, and common token formats.

REQ-API-001 — Every non-public endpoint SHALL require verified authentication. Tokens SHALL be scoped to identity, purpose, tenant/case, action, and lifetime; transmitted only over TLS-protected channels, revocable, and protected against replay where applicable.

REQ-API-002 — Authentication SHALL not imply authorization. Every endpoint, object reference, export, background job, callback, and integration operation SHALL enforce server-side endpoint/action/scope authorization and generic non-disclosing failure responses.

REQ-API-003 — High-risk operations SHALL require separate scopes and, where configured, step-up authentication or approval. Privileged machine links SHOULD use mTLS, but certificate validation SHALL supplement normal request authorization.

REQ-API-004 — Changes to roles, scopes, policies, trust, certificates, and integration permissions SHALL be reviewed, version-controlled, time-bounded for emergencies, and audited with actor, target, reason, outcome, and expiry.

## 6. Network egress and non-execution

REQ-NET-001 — All analysis workloads SHALL start with default-deny outbound and inbound network policy, including public/private/link-local/metadata addresses, peer containers, host gateways, and public DNS. Return traffic is permitted only for approved outbound connections.

REQ-NET-002 — Egress exceptions SHALL allowlist workload identity, case/job purpose, exact FQDN/IP/CIDR, port, protocol, proxy/gateway, owner, approval, and expiry/review. Wildcards and unrestricted ranges/ports are prohibited except approved emergencies.

REQ-NET-003 — Workloads SHALL use controlled DNS and an authenticated central proxy/gateway. Direct DNS, DoH/DoT, alternate interfaces, host networking, proxy bypass, DNS rebinding, and private/loopback/metadata resolution bypasses SHALL be blocked. FQDN authorization SHALL be enforced against resolved IPs at connection time.

REQ-NET-004 — TLS SHALL use validated organizational trust, TLS 1.2 minimum (TLS 1.3 preferred), approved ciphers, and no verification bypass. Gateway, DNS, firewall, and runtime logs SHALL be tamper-evident and include workload/image digest, case/job, destination, rule, outcome, and UTC time.

REQ-NET-005 — If policy engine, resolver, proxy, gateway, or required telemetry is unavailable, the workflow SHALL pause/terminate and deny new egress. Operators SHALL be alerted.

REQ-MAL-001 — Evidence, uploads, archives, documents, scripts, binaries, macros, browser caches, deleted data, and recovered commands SHALL never be executed, interpreted, actively rendered, imported for active processing, or opened with macros/plugins. File identification, hashing, metadata extraction, OCR, indexing, and static inspection operate on bytes only.

REQ-MAL-002 — Scanning/parsing SHALL occur in disposable, least-privilege, non-networked sandboxes with read-only input, private scratch, seccomp, and strict resource limits. Behavioral analysis, if ever authorized, requires separate documented approval, synthetic credentials, restricted simulated network, full telemetry, snapshot/revert, and teardown.

REQ-MAL-003 — State transitions SHALL be explicit (`received`, `quarantined`, `validated`, `scan-unavailable`, `rejected`, `accepted`, `derived`) and actor/job/reason audited. Only `accepted` enters ordinary analysis. Scanner failure is not clean.

REQ-MAL-004 — Detections, prohibited characteristics, attempted execution, parser errors, unexpected egress, and integrity mismatches SHALL quarantine or fail closed, alert, and retain source reference, hashes, scanner/rule versions, verdict, action, and UTC time. Quarantine never silently deletes or overwrites originals.

## 7. Audit integrity and defensibility

REQ-AUD-001 — Audit successful and denied authentication/authorization, evidence access/export/mutation/deletion, state transitions, jobs, policy/deployment/exception changes, secret metadata, integration events, scanner/parser decisions, egress, and audit failures.

REQ-AUD-002 — Events SHALL include actor/service, tenant/case, action, stable target/resource ID, outcome, reason, source/component, UTC timestamp with millisecond precision, correlation ID, parent/trace ID where applicable, and sequence/ingestion timestamp. Ordering shall not rely on wall clock alone.

REQ-AUD-003 — Canonical audit records SHALL be append-only and immutable to normal operators, with canonical serialization, prior-event hash, approved cryptographic integrity/authenticity mechanism, external checkpoints, and versioned key metadata. Verification SHALL detect modification, deletion, insertion, truncation, and reordering.

REQ-AUD-004 — Security-critical actions SHALL block or apply an approved compensating control if audit durability is unavailable. Buffers are bounded, protected, replay-safe, monitored, and deduplicated. Gaps, verifier failures, retention violations, and clock failures alert.

REQ-AUD-005 — Logs and audit exports SHALL omit secrets, full tokens/cookies, evidence contents, and unnecessary personal data. Audit read/export is separately authorized and itself audited. Retention, legal holds, deletion approvals, and audit/evidence separation SHALL be documented.

## 8. Verification and release acceptance

The test environment SHALL use synthetic tenants, cases, credentials, evidence, and malware canaries. Every test record retains test/requirement IDs, fixture hashes, image/config/policy/tool versions, UTC start/end, operator/CI identity, raw output, verdict, reviewer, and SHA-256 manifest outside supplied evidence directories.

Result states: PASS requires the expected control, no prohibited side effect, and retained reviewable evidence. FAIL includes leakage, mutation, execution, egress, secret disclosure, audit gap, or integrity change. BLOCKED/INCONCLUSIVE is treated as failure until rerun. Exceptions must identify owner, rationale, scope, compensating controls, expiry, and approval reference.

Mandatory release suites:

VER-ISO-01 — Two tenants/two cases: list, search, direct IDs, bulk APIs, download, export, mutation, callbacks, and queued jobs. Authorized same-scope actions succeed; every forged/missing cross-scope action is denied before access or side effect and is audited.

VER-PATH-01 — Fuzz traversal, absolute/UNC/drive, Unicode, reserved names, NUL, ADS, duplicate, symlink, hardlink, and separator variants. No outside-root write, link follow, overwrite, or collision succeeds.

VER-IMM-01 — Hash originals before/after; attempt write/delete/rename/truncate/chmod via every service/container. Original bytes and metadata remain unchanged; original mounts are not writable.

VER-POD-01 — Inspect Podman runtime, rootless mapping, mounts, namespaces, capabilities, seccomp, no-new-privileges, resource limits, and image digests. Runtime and policy fixtures reject rootful/privileged/host-access/noncompliant workloads.

VER-UPL-01 — Oversize streaming, false Content-Length, quota/count races, type mismatch, malformed formats, alternate ingestion paths, and retries. Limits are atomic/bounded, partial output is removed, and no unvalidated object is accepted.

VER-ARC-01 — Traversal/link/device/archive bomb/forged header/nesting/unsupported/encrypted/stalled parser fixtures. Extraction stops at observed limits, kills process groups on timeout, creates no special files, writes no outside root, and retains safe failure state.

VER-MAL-01 — Script, macro document, executable, web shell, archive payload, preview/OCR/index canary, and EICAR fixture. No process/marker/active preview/network connection occurs; detections quarantine and alert; scanner/quarantine failure is not clean.

VER-API-01 — Missing/invalid auth, wrong action/scope, IDOR, expired/revoked/replayed tokens, rate/size limits, and mTLS identity tests. Generic denial, no side effect/existence leak, and durable correlated denial events are required.

VER-SEC-01 — Secret scanning and runtime redaction across images, `/proc`, args, environment, logs, traces, metrics, crash output, URLs, and browser storage. Injected secrets fail build/admission and never appear at runtime.

VER-AUD-01 — Positive/negative events, UTC/correlation completeness, tamper trials (modify/delete/insert/reorder/truncate), checkpoint verification, retention/legal hold, clock drift, and audit-sink outage. Every tamper class is detected; critical actions cannot silently lose history.

VER-NET-01 — Unallowlisted public/private/host/metadata, IPv6, raw sockets, DNS/DoH/DoT, proxy bypass, DNS rebinding, weak TLS, image/policy drift, and outage tests. Only exact approved proxy traffic succeeds; policy/telemetry outage fails closed.

MANUAL-01 — Independent adversarial review SHALL attempt client-check removal, direct-object bypass, concurrent races, container boundary escape, secret discovery, parser fallback, active preview, raw network bypass, and audit manipulation. Exact commands/requests, expected/observed results, timestamps, and telemetry are retained.

Release acceptance requires every mandatory requirement mapped to a passing automated/deployed test and relevant manual check; all ingestion paths and failure/recovery paths exercised; original hashes stable; no untrusted execution, cross-scope access, uncontrolled egress, or secret emission; runtime controls and audit integrity verified; and an authorized reviewer signed the decision. “Not tested,” “not observed,” and inconclusive results are not PASS.

## 9. Operational evidence, exceptions, and limitations

Retain policy/configuration versions, image and scanner digests, parser versions, egress/DNS/proxy rules, raw test output, alert and quarantine records, audit verifier output, and release manifest in a restricted tamper-evident store. Preserve failed evidence and remediation/retest links.

Every exception SHALL be time-bounded and list owner, reason, affected tenant/case/service, exact privilege or egress, compensating controls, monitoring, approval, and expiry. A change to images, mounts, privileges, network, parser/scanner, authorization, storage, queue, secrets, or audit format triggers affected regression suites.

This specification does not establish legal conclusions, actor attribution, or absence of compromise. It establishes technical controls and evidence needed for a defensible workflow; gaps must be reported as limitations and drive next-collection or remediation work.

## 10. Source requirement sections

This consolidation incorporates the upstream security/isolation, upload/archive, secrets/API/audit, network/non-execution, and verification/acceptance requirement sections. The upstream documents remain useful as detailed implementation and test references; this file is the cross-cutting baseline for architecture and release review.
