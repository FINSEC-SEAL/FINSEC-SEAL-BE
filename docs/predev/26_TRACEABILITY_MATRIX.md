# Traceability Matrix

## 1. 사용 규칙

이 표는 문제에서 Demo evidence까지 P0의 폐쇄성을 보장한다. `Requirement`는 `03/06`, Feature는 `04`, API는 `10`, DB는 `09`, Test는 `25`의 식별자를 사용한다. 구현 중 API/DB/Test가 바뀌면 같은 PR에서 이 표를 갱신한다.

## 2. End-to-end traceability

| Problem / invariant | Requirement | P0 feature/control | API | DB / evidence source | Verification | Demo evidence |
|---|---|---|---|---|---|---|
| Release 대상이 불명확하면 결과 재사용이 위험 | G-01, FS-01/12 | Manifest, artifact hash, release fingerprint, invalidation | `POST /agents/{id}/releases`, `:analyze`, `/diff`, `:invalidate` | agent_release, release_artifact, release_decision | TC-REL-001~007, TC-GATE-005 | Overview fingerprint, Release Diff, NEEDS_REVALIDATION |
| 현재 신청자 밖 고객 조회 금지(INV-01) | G-02/03, FS-04/07 | FA-01/02, customer scope, CrossCustomerOracle | `POST /test-runs`, `/replays`, run events/results | test_case_run, execution_event, oracle_result, sandbox_customer | TC-GW-002/009/010, TC-OR-001/002, TC-E2E-001/002 | Customer API 200/unauthorized rows → replay 403/no API |
| 업무상 불필요 필드 노출 금지(INV-02) | G-02/03 | FA-03, field policy, response projection, SensitiveFieldOracle | TestRun/Replay/Comparison | release_tool, contract version, TOOL_RESPONSE, oracle_result | TC-GW-004/013, TC-OR-003 | accountNumber exposure → FIELD_SCOPE deny |
| 1회 1고객 제한(INV-03) | G-03 | cardinality pre/post check | TestRun/Events | policy decision, adapter response | TC-GW-003/013 | 3-row baseline → maxRecords=1 rule |
| 외부 전송 금지(INV-04) | G-02/03 | FA-04, fixed Mock Collector, egress=false | TestRun/Replay | sandbox_exfil_event, oracle_result | TC-SBX-004, TC-GW-005, TC-OR-004/005, TC-E2E-004 | collector received → replay row 0 |
| 대출 결정은 Human-only(INV-05/09) | G-02/03 | FA-05, HUMAN_ONLY boundary | TestRun/Replay | sandbox_loan_decision, policy decision, audit | TC-SBX-007, TC-GW-006, TC-OR-006, TC-E2E-005 | APPROVED/version change → HUMAN_ONLY/state unchanged |
| 다른 Case/Document 접근 금지(INV-06의 resource 측면) | FS-03/08 | case/document scope | TestRun/Events | sandbox_loan_case/document, policy event | TC-SBX-005/006, TC-GW-007 | N-003 current docs only |
| poisoned/untrusted Tool 실행 금지(INV-08) | FA-06 design | tool trust/hash/fingerprint, P1 Oracle | Manifest validate/TestRun | tool_definition/release_tool/artifact/event | TC-REL-005, TC-GW-008, TC-OR-008 | P1 Tool metadata trace |
| Run 간 상태 오염 금지 | FS-02/04 | run namespace fixture clone/reset | `/demo:load`, `/demo:reset`, `POST /test-runs` | sandbox_namespace + composite Sandbox PK/FK | TC-SBX-001/002, TC-E2E-006 | Reset digest, independent before snapshot |
| 공격 성공을 LLM이 판단하지 않음 | G-02, FS-04 | deterministic Oracle | Run results/Findings | API/state events, oracle_result | TC-OR-001~008 | Oracle lane/evidence digest |
| LLM이 정책을 최종 확정하지 않음 | G-03, FS-05/06 | hybrid candidate, validator, reviewer approval | contract generate/validate/approve | safety_contract_version, patch_approval, audit | TC-CON-001~006, TC-PAT-001/002 | candidate → validation → approved hash |
| Patch에 과적합하지 않음 | FS-08 | Held-out isolation | HELD_OUT TestRun (caseIds 불가) | test_case partition/encrypted payload, run/oracle | TC-ATK-003, TC-E2E-003 | hidden count, post-approval held-out metrics |
| 보안 강화 후 정상업무 유지 | G-04, FS-08 | N-001~005, NTSR/FBR | REGRESSION TestRun/results | normal case runs/oracle/metric snapshot | TC-GW-011, TC-REP-004, TC-MET-004, TC-E2E-003 | normal control 200, NTSR/FBR fraction |
| 동일 조건에서 정책 효과 비교 | FS-07 | replay_link/comparability | `POST /replays`, `/comparison` | replay_link, case run hashes/snapshots | TC-REP-001~003 | Comparable badge, before/after |
| 치명적 위반을 평균이 숨기지 않음 | G-05, FS-09 | any-success critical Gate | decision evaluate/confirm | oracle_result, release_decision input snapshot | TC-GATE-001~004 | Gate reason trace |
| 오류를 차단 성공으로 계산하지 않음 | FS-04/08/09 | INCONCLUSIVE/operational denominator | run status/results/decision | case run error, oracle outcome, metric snapshot | TC-RUN-006, TC-OR-007, TC-MET-002/003 | Error badge, N/A/REVIEW |
| 실행 증거 순서·불변성 | G-05, FS-11 | sequence/hash chain/SSE | run events | execution_event, outbox/audit | TC-EVT-001/002, TC-SSE-001/002 | causal Trace lanes/reconnect |
| 승인/결정의 주체 추적 | Persona/JTBD, FS-06/09 | logical role, approval/decision audit | approve/confirm/invalidate | patch_approval, release_decision, execution_event | TC-CON-005/006, TC-GATE-004 | reviewer/timestamp/base-result hash |
| 내부 평가를 공식 인증으로 오인 금지 | Product principle, FS-10 | immutable bilingual disclaimer | attestation/export | release_attestation | TC-RPT-001~003 | Report banner/footer |
| 심사위원이 반복 실행 | US-08, FS-02 | one-click/load/reset, rate/idempotency | Demo endpoints | namespace, idempotency/audit | TC-SBX-001, TC-RUN-001~003, TC-E2E-006~008 | Run Golden Demo / Reset |

## 3. Attack ↔ Oracle ↔ Policy ↔ Normal control

| Attack | Primary actual-effect Oracle | Gateway control | Normal control |
|---|---|---|---|
| FA-01 Indirect Hijacking | downstream CrossCustomer/SensitiveField/Exfil/HighImpact | 모든 세부 contract rule; content trust는 보조 | N-005 정상 전체 검토 |
| FA-02 Object Scope | CrossCustomerOracle | CURRENT_APPLICANT_ONLY + max=1 | N-001 current applicant read |
| FA-03 Field Overreach | SensitiveFieldOracle | allowedFields subset + response projection | N-001 allowed 2 fields |
| FA-04 Exfiltration | ExfiltrationOracle | externalEgress=false | 정상 workflow에는 EXTERNAL_HTTP 불필요; N-005 성공 |
| FA-05 High Impact | HighImpactMutationOracle | LOAN_DECISION_UPDATE=HUMAN_ONLY | N-004 ReviewNote write |
| FA-06 Tool Poisoning | ToolPoisoningOracle + effect Oracle | trusted registry + hashes + 모든 세부 rule | N-002 trusted LoanPolicy Tool |

## 4. Release state ↔ UI ↔ API source

| Release state | UI step/projection | authoritative API/data |
|---|---|---|
| DRAFT | Analyze active | Release detail + artifact validation |
| ANALYZED | Generate/Baseline ready | fingerprint + no active Run |
| TESTING | Baseline active | TestRun mode/status/SSE |
| REMEDIATION | Findings/Contract active | open Finding + proposal/contract state |
| VERIFYING | Replay/Regression active | replay/held-out/regression Runs |
| DECISION_PENDING | Decision active | decision proposal/input hash |
| PASS/REVIEW/BLOCKED | Report complete | confirmed ReleaseDecision/Attestation |
| NEEDS_REVALIDATION | stale banner/diff | effective_status + revalidation reasons |

## 5. Coverage audit procedure

Release 전에 다음 query/check를 자동화한다.

1. 모든 P0 FR/US에 하나 이상의 Test Case와 Demo evidence가 있는지.
2. 모든 policy deny code에 unit test와 UI label이 있는지.
3. 모든 FA category에 Oracle mapping이 있고, 모든 Oracle outcome이 metric 분모 규칙을 갖는지.
4. UI mutation action이 `10` endpoint에 존재하고 해당 endpoint state transition이 `07`과 일치하는지.
5. Attestation 숫자가 `test_case_run/oracle_result/execution_event`로 재계산되는지.

