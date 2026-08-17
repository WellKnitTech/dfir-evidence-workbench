# Governance, Privacy, Retention, and Release Operations

Status: alpha/beta operational policy. Scope: evidence governance controls that
sit above the technical requirements in `security-defensibility-requirements.md`,
`evidence-integrity-chain-of-custody.md` (t_0da4fc9e), and the retention/backup
design from t_349fa125. This is operational policy, not legal advice; the case
lead and org privacy/legal function confirm jurisdiction-specific obligations.

Every control below has an **owner** (accountable role, not a person's name),
a **test/evidence source** (how a reviewer verifies the control is real, not
aspirational), and an explicit **exception process**. No control ships without
all three.

## Exception process (applies to every control)

A control may be exempted only with: written reason, exact scope (tenant/case/
service), owner, compensating control, monitoring, expiry date, and an
approver distinct from the requester. Exceptions are logged in the audit trail
(REQ-AUD-001) and reviewed at each access review cycle. An expired exception
reverts to enforced-by-default; there is no silent renewal.

## Policy-to-control matrix

| Area | Control | Owner | Test / evidence source | Exception process |
|---|---|---|---|---|
| Retention schedule | Storage-category retention periods enforced per the matrix in the retention/deletion/backup policy; expiring items flagged before deletion | Case Lead (per case), Platform Owner (schedule defaults) | Automated retention-scan job output + manual sampling of flagged items each quarter | Per-item hold documented below; schedule-wide changes require Platform Owner + Privacy Officer sign-off |
| Legal hold | Any case/evidence item under hold is exempt from deletion and disposition regardless of retention expiry; hold state is a first-class, auditable field | Case Lead requests; Legal/Compliance Officer approves and can only be lifted by the same role | Query showing all `on_hold=true` items are excluded from the deletion job; hold create/lift events in audit log (REQ-AUD-001/002) | Hold release requires Legal/Compliance Officer approval distinct from the requester; reason and date recorded |
| Deletion / disposition approval | No evidence, derivative, or case record is destroyed without a recorded case-lead authorization (chain-of-custody rules, "Derivatives, exports, and destruction") | Case Lead authorizes; Platform Operator executes | Disposition record: authorizer, method, date/time, witness/approver, destruction receipt; sampled against actual deletions | Emergency deletion (e.g. legal order) requires two-person approval (Case Lead + Legal/Compliance) recorded before execution, never after |
| Access review | Case/tenant access lists reviewed on a fixed cadence; access not tied to an active case/role is revoked | Security Owner | Quarterly access-review report: reviewer, scope reviewed, revocations made, sign-off date | Deferred review requires Security Owner + Platform Owner justification, capped at one cycle |
| Operator separation of duties | No single operator role can both approve and execute high-impact actions (evidence export, deletion, retention override, case closure, credential/policy changes) per REQ-AUTH-004; dual control uses a distinct approving principal | Security Owner defines roles; Platform Owner enforces in IAM config | Role/permission matrix review + attempted self-approval test (must fail) each release cycle | Break-glass single-operator action requires post-hoc Security Owner review within 24h and is itself audited |
| Privacy / PII handling | Personal data in metadata, audit logs, and exports is minimized, access-restricted, and never embedded in evidence-analysis derivatives beyond what the case requires; redaction is recorded, not silent (chain-of-custody "Derivatives, exports, and destruction") | Privacy Officer (policy), Case Lead (per-case application) | Sample export/audit review confirming no unnecessary personal data (REQ-AUD-005) and redaction records exist for redacted report copies | PII retained beyond case need requires Privacy Officer approval, documented legal basis, and its own retention clock |
| Case closure | Closure requires: all holds resolved, disposition decisions recorded, final report cites evidence IDs/hashes for every finding, chain-of-custody assumptions and limitations stated (chain-of-custody "Required verification gates") | Case Lead | Closure checklist artifact attached to case record; spot-checked at access review | Closure with open items requires Case Lead + Platform Owner documented rationale and follow-up date |
| Chain-of-custody export | Exported custody history is a complete, tamper-evident append-only record (chain-of-custody "Chain-of-custody event model"); export itself is a recorded, authorized action (REQ-AUTH-004) | Case Lead requests; Platform Operator executes | Export includes verification that the record set is unmodified since last checkpoint (REQ-AUD-003); sampled against source events | Partial export (e.g. redacted for disclosure) requires Legal/Compliance approval and is logged as its own custody event |
| Support / escalation | Integrity failures, security incidents, and access anomalies escalate to a named on-call owner within a defined SLA; no operator sits on an unresolved integrity failure (chain-of-custody "Stop on integrity failure") | Platform Owner (on-call rotation) | Incident/escalation log with detection time, escalation time, resolution; sampled for SLA adherence | Missed SLA logged with root cause; no silent misses |
| Change management | Changes to images, mounts, privileges, network, parser/scanner, authorization, storage, queue, secrets, or audit format are reviewed, version-controlled, and trigger the affected regression suites (security-defensibility-requirements.md §9) | Platform Owner | PR/change record linked to the triggered test run; sampled at release gate | Emergency change ships first with post-hoc review within 24h, logged as an exception |
| Staging parity | Staging environment configuration (image digests, secrets injection method, network policy, auth mode) matches production shape before any release gate signs off | Platform Owner | Diff of staging vs. prod compose/config plus a passing staging run of the mandatory release suites (security-defensibility-requirements.md §8) | Documented, time-bounded parity gaps require Platform Owner + Security Owner approval and are listed as residual risk in the release decision |
| Release sign-off | A release is not accepted on tests alone; an authorized reviewer signs the readiness decision after mandatory suites, manual adversarial review, and this governance matrix are current (security-defensibility-requirements.md §8, release-checklist.md) | Release Approver (role distinct from the implementer) | Signed release-readiness report naming residual risks and rollback plan | No release-sign-off exceptions; a release that cannot pass ships as a documented rejection, not a waived approval |

## Roles referenced

Case Lead, Legal/Compliance Officer, Privacy Officer, Security Owner, Platform
Owner, Platform Operator, Release Approver. Roles may be held by different
people per engagement; the separation-of-duties control above is what
prevents role collapse from becoming a single point of failure.

## Relationship to existing documents

This matrix does not restate technical controls already specified in
`security-defensibility-requirements.md` (isolation, secrets, audit integrity,
network) or the chain-of-custody handling rules; it adds the governance layer
those documents assume: who decides, who reviews, and how an exception is
recorded. Retention periods, legal-hold mechanics, and backup/restore detail
live in the retention/deletion/backup policy produced under t_349fa125.
