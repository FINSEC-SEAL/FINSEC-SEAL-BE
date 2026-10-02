# A committed Release audit notification source

This feature connects the two existing Release mutations to the local Spring application event bus after their physical outer transaction commits. Role A owns receipt storage and publication. Role C owns any subsequent policy/cache consumption; this change provides no consumer implementation or acknowledgement.

## Eligible source and transaction boundary

`ReleaseService.invalidate` and `applySafetyContractHash` capture the actual `AuditService.append` return. Only `AGENT_RELEASE_INVALIDATED` and `RELEASE_CONTRACT_FINGERPRINT_APPLIED` for the expected workspace and Release are eligible. The helper requires non-null audit/workspace/resource UUIDs and occurredAt, matching AGENT_RELEASE resource type and corresponding action. It preserves actor, digests and time, including equal digests, and detaches the mutable metadata tree.

Both owner paths require an actual, synchronized, writable transaction before their first repository/service I/O. Registration checks again after snapshot construction. The existing REQUIRED transaction remains authoritative: contract approval persists APPROVED before calling the Release mutator and writes its approval audit afterward. Mutator return therefore does not publish; the actual outer afterCommit callback makes one local publication attempt. Rollback, rollbackOnly and failed physical commit do not publish. AuditService.appendRequiresNew remains independent and does not acquire a Release source callback.

Receipt validation, copy and synchronization registration failures propagate before commit, allowing the existing owner transaction to roll back. After commit, only RuntimeException thrown by synchronous publishEvent is contained. The constant WARN contains actual audit UUID, Release UUID, allowlisted action and a cause class sanitized to ASCII and bounded to128 characters. It receives no Throwable, exception message, stack, actor, metadata or digest. Error is not caught. There is no callback database operation, new transaction, compensation, immediate fallback or retry.

The narrow response guarantee concerns this synchronous publication RuntimeException after successful owner commit. Logging/JVM/process failures and arbitrary unrelated response failures have no universal success guarantee. A listener can fail before later listeners execute. Successful publish return is not a C ACK.

Existing DTO/internal wiring is an owner-controlled local receipt source, not cryptographic authentication of arbitrary forged internal Records. A consumer must apply its own eligibility checks. Metadata is detached from the owner receipt, but JsonNode remains mutable. This feature does not establish exactly-once delivery, durable fanout, restart recovery, multiple-JVM delivery or ACK/retry completion. Those A/C limitations are distinct from skipped B dependencies.

## Task-derived verification controls

The integration class uses PostgreSQL17.11 Testcontainers and RANDOM_PORT SpringBootTest, with actual services and PlatformTransactionManager and no test-managed rollback. Its callback obtains an independent DataSource connection, records committed facts/errors before a deliberate listener throw, and asserts errors in the test body. It compares the original receipt time to the event exactly and the persisted timestamptz at PostgreSQL microsecond precision (difference≤1microsecond).

| Control | Integration method / intended observation |
|---|---|
| AC-PG-001 | normalApprovalWaitsForPhysicalOuterCommitAndObservesAllApprovalWrites: actual create/validate/approve with strong ETags; approved version and later approval audit visible together |
| AC-PG-002 | terminalInvalidationCommitsLatestDecisionEvidenceAndSameDigestReceipt: latest Decision invalidation, NEEDS_REVALIDATION and committed receipt |
| AC-PG-003 | normalApprovalWaitsForPhysicalOuterCommitAndObservesAllApprovalWrites: owner return with event0, then physical outer commit and event1; realReceiptMetadataIsDetachedBeforeOuterCommitAndEqualDigestApplyStillDelivers supplements equal-digest delivery |
| AC-PG-004 | approvalExceptionAndRollbackOnlyRestoreOwnerAndAuditWithoutDelivery; unrelatedRequiresNewAuditSurvivesOuterRollbackWithoutReleaseNotification |
| AC-PG-005 | deferred23514OccursOnlyAtPhysicalCommitAfterActualRegistrationAndSuccessfulFlush: producer-specific synchronization and successful flush precede deferred23514; owner/audit rollback and event0 |
| AC-PG-006 | bothActualOwnerPathsRefuseBeforeFirstCollaboratorIo: unproxied noTx and synchronization-only SUPPORTS; failuresAfterRealAppendRollBackOwnerDecisionAndAudit supplements test-only receipt/copy/registration failures |
| AC-PG-007 | bothActualOwnerPathsRefuseBeforeFirstCollaboratorIo: real readOnly outer transaction, zero collaborator I/O and no owner/audit/event delta |
| AC-PG-008 | independent callback receipt/state comparison; realReceiptMetadataIsDetachedBeforeOuterCommitAndEqualDigestApplyStillDelivers |
| AC-PG-009 | actualHttpSucceedsAfterSynchronousListenerRuntimeFailureAndLogsOnlyBoundedSafeFacts: actual approval/invalidate HTTP200, real append/callback thread equality, committed rows, safe WARN and one attempt |

These IDs and A-CNOT-001..006 are task-derived controls, not newly invented normative TC IDs. Existing Release, concurrency, prompt rollback-audit and Contract persistence integration classes provide affected regressions, including immutability, stale ETags and competing approvals. Their tests do not replace actual B runtime/trial/certification evidence.

Normal setup uses unique actual Agent/Manifest1.1 creation/analyze and the existing fixture-only REMEDIATION seam before Contract create/validate/approve. Terminal setup uses a separately committed synthetic PASS Release and unique latest confirmed Decision from the existing legal fixture. It is not a real D Gate PASS/certification. The requiresNew control uses a separately committed lawful unrelated Release and checks the returned audit receipt by exact UUID/workspace/resource/action, preserving V6/V16 scope guards.

Late23514 setup commits actual approval first, commits REMEDIATION separately without changing its hash, then reads a fresh entity and applies a different valid-shaped unapproved hash through the real owner. REMEDIATION→VERIFYING permits the existing BEFORE guard; successful flush precedes the DEFERRABLE matching-APPROVED guard failure at physical commit. Starting from VERIFYING can instead fail55000 early and cannot prove this control. No migrations/triggers were changed.

The context asserts the real JpaTransactionManager, nestedTransactionAllowed=false, physical read_only/isolation and synchronous multicaster/caller thread. NESTED/savepoint, custom manager or async multicaster changes require renewed independent review; their behavior is outside this evidence.

## Current evidence and delivery state

Parent is actual unmerged SSE PR139 head `f700c7e1c2584156c8089e50f4950eee6ce3968c`, not merged dev. Fresh producer Run is `20261002T174337Z-bbbfd0ba`. Exactly five A-owned paths comprise helper, helper tests, ReleaseService wiring, this PG class and this handoff. C/B/D/FE/auth/SSE product changes are outside the delta.

At handoff creation, the one-attempt fresh helper execution passed39 tests with failures/errors/skips0. Its raw stdout/stderr, exit0 and XML are preserved under orchestration evidence `a-producer-resume-source-only-20261003/UNIT2_FOCUSED_20261002T184744Z`. Full pre baseline had3945 cases with one existing FINSEC_AI_LIVE_E2E skip; it is baseline evidence, not implementation coverage. Supervisor98dca7df FAIL and cadence37.12-minute WARN remain immutable; correction d451940d accepted the lawful requiresNew fixture and authorized pending PG completion after saved Root GO.

The first fresh affected execution completed at `2026-10-02T19:58:01.024767Z`, exit0, with five tasks executed and retry0. New PG controls passed15/15; existing Contract persistence17, Release7, Release concurrency3 and prompt rollback-audit1 also passed, for43 tests/failures0/errors0/skips0. All AC-PG-001..009 have passing assertion-level evidence through the methods above. The actual context satisfied JpaTransactionManager/nested-disabled, physical READ_COMMITTED/read_only controls and synchronous caller-thread assertions. Both HTTP200 listener-failure controls passed. These are bounded fixture and local process results.

Exact argv, source hashes at execution, raw stdout/stderr and fresh XML5 are preserved in orchestration evidence `a-producer-resume-source-only-20261003/UNIT3_AFFECTED_20261002T195722Z`. The new PG XML SHA256 is `b6608a2436d4974a9ee807059062562dfa350bcca5032616148d92aeec263acd`. Existing unrelated compiler/JVM warnings remain raw. Only this evidence status was updated after that execution; production and test files remained unchanged.

Mandatory fresh full BE `./gradlew test --rerun-tasks --no-build-cache --no-daemon` (timeout1200), exact tested final checkpoint with --run-tests, same-Run post with all five specialists plus Orchestrator, and role-scoped Git packaging are pending. No product edits follow final Supervisor approval. B unfinished runtime/history/required-trials/held-out certification remain SKIPPED_PER_USER/unknown, not completed.
