# C published Gateway source composition handoff

## Status and scope

Execution of `PublishedGatewaySourceCompositionIntegrationTest` is **PENDING**. This handoff describes the new C-owned test source and the evidence it is intended to collect; it records no new passing test, final acceptance, commit, publication, or post result.

The current development Run is `20261006T150001Z-ad9adba1`. Its independent second-unit checkpoint `20261006T155124Z-dbbe2410` is `APPROVED_WITH_NOTES` and permits only the composition test and this handoff in the selected P/M pair. The published stored-reviewer main/unit and integration/doc units have already been incorporated under their separate checkpoints. Historical failed review and cadence records remain preserved.

Root must select the exact two new paired artifacts, bind 540 → 542 selected leaves with identical P/M bytes and modes, and obtain the immediate independent source-only checkpoint. That implementation decision provides no test execution authority. Separately scoped execution, exact-final configured testing and tested Supervisor approval, fresh truthful actual-P Git evidence, and the unchanged same-Run `post --with-agents` are still pending. Completion and delivery must remain pending until every required gate succeeds.

## Composition under test

The fixture uses PostgreSQL `17.11-alpine` and the minimal lawful published provider pattern: real Agent and Release creation/analyze, owner transactions through TESTING and REMEDIATION, and actual Safety Contract create/validate/approve. Both target and other Releases receive independent A-issued reviewer sessions and real cookie/CSRF authenticated Run admission in SEAL_REPLAY. The Run, executing CaseRun, active sandbox namespace and exact stored TOOL_PROPOSED event form each invocation key. The positive fixture never inserts a reviewer grant directly.

A real `StoredGatewayReviewerContextSource(HikariDataSource, StoredRunReviewerAuthoritySource, StoredGatewayPreCallScopeSource)` resolves each exact key outside an ambient transaction with a five-second budget and a 2,000 ms Hikari connection timeout. Assertions bind workspace, actor, reviewer role, verified opaque session digest and the full key. Fixed scoped snapshots verify that these reviewer lookups preserve stored state.

The actual Spring-proxied `GatewayApprovedPolicySourceService.load` receives the verified resolution's reviewer outside a caller transaction. Its own writable REPEATABLE_READ transaction performs real A approval/current Release checks and can append legitimate access audits. The returned source is checked against Run, CaseRun, mode, status, approved version identity, resource hash, policy hash and copied policy. A spy counts actual semantic `validate` invocations only after both fixture approvals; no positive result is stubbed.

## Required evidence

- Cold authorized target and other reads each add one semantic validation; subsequent warm reads add none. Cache inspection uses the existing synchronized proxy-target pattern and retains nonempty target/other witnesses with no pending fill. It assumes no global empty cache.
- The actual `ReleaseService.applySafetyContractHash` applies the already approved equal policy hash inside an outer owner transaction. Before physical commit, cache/epoch and committed-event observations remain unchanged. After outer exit, only target entries are evicted, other and unrelated keys are retained, the epoch increases once, and pending fills are zero. An observer on the actual A bus collects the release audit receipt and checks its persisted visibility through a separate physical connection. Callback errors are collected and asserted after exit.
- A subsequent real stored reviewer resolution and approved-source proxy read makes the target cold again and adds exactly one semantic validation; the other remains warm. Equal-hash application preserves the lawful admission and current policy binding.
- Parameterized thrown-exception and `setRollbackOnly` paths use the same real owner write. After physical rollback exit, the target Release row, owner audit count, complete cache keys/epoch/pending, fixed scoped stored snapshots and committed-event observations match their baseline.
- The warm denial test first revokes the actual target-issued session, then takes its negative snapshot and clears previous source/validator interactions. An actual `LoanReviewPolicyGateway` receives a recording wrapper over the real stored provider and the actual approved-source proxy spy. Its ToolInvocation overload must return cause-free `AUTHENTICATION_REQUIRED`, the code-name message and `successfulSecurityBlock=false`. Reviewer calls equal one with the exact key and a positive budget at most five seconds. Approved source, validator, baseline, observations, transaction manager, projections, owner reader, facts assembler, events, mutations, redaction and adapter remain uncalled.
- The negative comparison occurs after the existing two deadline permits and Hikari active connections settle within eight seconds. It does not mutate the barrier, close the application pool, or claim global quiescence. Sixteen fixed scoped table queries cover Run/CaseRun, grants/revocation, namespace/sandbox, events/counters, V13 idempotency by `test_case_run_id`, and relevant audits. They bind fixture values and return only row counts and digests.

Actual authorized positive source access audits are legitimate writes and are distinct from the revoked-grant negative snapshot. A revoked session may leave inert warm cache metadata; those entries cannot confer reviewer authority.

The existing committed-cache tests retain their physical deferred database failure and pending-fill interleaving coverage unchanged. The new composition class does not duplicate those algorithms or alter existing test bytes.

## Ownership and remaining evidence

| Owner | Boundary and current evidence gap |
| --- | --- |
| A | Owns credentials, admission/grants, persistence, Release transitions and committed audit publication. This test consumes ordinary APIs; it changes no A code, storage contract or publisher. |
| B | Owns pre-call scope, runtime observations/history, adapter dispatch and execution. Stored scope is consumed as published. Full positive observations, history/execution and deployed ENFORCE witnesses remain pending. |
| C | Owns stored reviewer/approved policy source and cache composition. The new test checks authority, policy/cache and commit/rollback boundaries without changing constructors, cache algorithms or application wiring. |
| D | Owns Oracle, finding, metrics and Gate decisions. The fixture supplies no D verdict or successful defense claim. |

Default Gateway flags remain disabled. No positive fake observations bean is installed and no B runtime code is changed. Manual real-source/proxy composition is fixture evidence; it is not production factory wiring, positive B dispatch, deployed ENFORCE, attack-defense success or global no-state-delta proof.

## Review and delivery

The selected actual delivery worktree remains P (`role-c-committed-cache-runtime/FINSEC-SEAL-BE`); M is its regular source/test review mirror. The published provider source S and the cache/Common/A140 baselines remain immutable. Preserve the user's `gradlew.bat` change and exclude it from staging.

Current PR #141 already carries a large feature scope. After all actual required gates and Root's publication selection, reviewable history should use small Conventional Commits with role `c`: one exact provider-incorporation commit and one coupled composition-test/handoff commit where appropriate. Both belong to the same coherent existing PR #141. This document authorizes no Git mutation, push, merge, PR closure or publication. Final post and delivery remain pending.

