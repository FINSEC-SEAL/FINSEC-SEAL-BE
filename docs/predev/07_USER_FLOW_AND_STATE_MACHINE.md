# User Flow and State Machines

## 1. Demo Golden Flow

```mermaid
flowchart TD
  Start["Demo Agent 선택"] --> Rel["Release Candidate 선택"]
  Rel --> Analyze["Manifest 분석 / fingerprint"]
  Analyze --> Base["Baseline Security Test"]
  Base --> Effect["Mock API 실제 합성 side effect"]
  Effect --> Oracle["Deterministic Oracle Finding"]
  Oracle --> Cause["Trace / Root Cause"]
  Cause --> Proposal["Safety Contract + Policy Patch Proposal"]
  Proposal --> Approve{"Reviewer 승인?"}
  Approve -- No --> Proposal
  Approve -- Yes --> Replay["동일 공격 Replay"]
  Replay --> Deny["Gateway 403 / side effect 0"]
  Deny --> Held["Held-out Attacks"]
  Held --> Normal["Normal Regression"]
  Normal --> Gate{"Release Gate"}
  Gate --> Decision["PASS / REVIEW / BLOCKED"]
  Decision --> Attest["Internal Release Attestation"]
```

## 2. Release state machine

요청 초안의 baseline 결과를 Release state와 분리했다. `VULNERABLE/BASELINE_SAFE`는 Run result이며 Release lifecycle은 다음과 같다.

```mermaid
stateDiagram-v2
  [*] --> DRAFT: release created
  DRAFT --> ANALYZED: manifest valid + fingerprinted
  ANALYZED --> TESTING: baseline run starts
  TESTING --> REMEDIATION: reportable finding exists
  TESTING --> VERIFYING: no finding / verify requested
  REMEDIATION --> VERIFYING: contract approved + replay starts
  VERIFYING --> DECISION_PENDING: required suites complete
  DECISION_PENDING --> PASS: gate pass + reviewer confirm
  DECISION_PENDING --> REVIEW: uncertainty / threshold / reviewer lower
  DECISION_PENDING --> BLOCKED: critical or threshold failure
  PASS --> NEEDS_REVALIDATION: fingerprint trigger
  REVIEW --> NEEDS_REVALIDATION: fingerprint trigger
  BLOCKED --> NEEDS_REVALIDATION: new release artifacts
  NEEDS_REVALIDATION --> ANALYZED: new validation cycle
```

| 현재 | 허용 명령 | 다음 | Guard |
|---|---|---|---|
| DRAFT | analyze | ANALYZED | manifest valid |
| ANALYZED | baseline start | TESTING | active run 없음 |
| TESTING | run complete | REMEDIATION/VERIFYING | result persisted |
| REMEDIATION | approve contract | VERIFYING | approved version |
| VERIFYING | all required complete | DECISION_PENDING | no excessive operational errors |
| DECISION_PENDING | confirm decision | terminal | gate constraints |
| terminal | artifact change/invalidate | NEEDS_REVALIDATION | trigger evidence |

## 3. TestRun state machine

```mermaid
stateDiagram-v2
  [*] --> QUEUED
  QUEUED --> PREPARING: worker lease
  PREPARING --> RUNNING: snapshot ready
  RUNNING --> CANCELLING: cancel requested
  CANCELLING --> CANCELLED: safe checkpoint
  RUNNING --> COMPLETED: all required case runs terminal
  PREPARING --> FAILED: fixture/integrity error
  RUNNING --> FAILED: operational error threshold exceeded
  QUEUED --> CANCELLED: cancel before lease
```

- `mode`: `BASELINE`, `SEAL_REPLAY`, `HELD_OUT`, `REGRESSION`.
- Terminal status와 security outcome을 분리한다. `COMPLETED` run에도 attack success가 있을 수 있다.
- Worker lease는 30초 heartbeat; 90초 미갱신 시 recovery worker가 재개하되 completed case는 재실행하지 않는다.

## 4. TestCaseRun state machine

`PENDING → EXECUTING → EVALUATING → PASSED|FAILED_SECURITY|FAILED_FUNCTIONAL|ERROR|CANCELLED`.

- attack의 `PASSED`는 invariant 유지(공격 실패)를 뜻한다.
- `FAILED_SECURITY`는 oracle=`ATTACK_SUCCESS`.
- normal의 `FAILED_FUNCTIONAL`은 expected output/state 불충족 또는 false block.
- trial은 같은 TestCase 아래 독립 TestCaseRun row다.

## 5. Finding state machine

```mermaid
stateDiagram-v2
  [*] --> OPEN: oracle attack success
  OPEN --> TRIAGED: reviewer acknowledges
  TRIAGED --> PATCH_PROPOSED: valid proposal
  PATCH_PROPOSED --> MITIGATED: approved contract replay blocks + evidence
  PATCH_PROPOSED --> TRIAGED: proposal rejected
  MITIGATED --> REGRESSED: later attack succeeds
  OPEN --> ACCEPTED_RISK: governance records rationale
  ACCEPTED_RISK --> REGRESSED: revalidation
```

Critical finding의 `ACCEPTED_RISK`는 Release PASS를 허용하지 않고 REVIEW/BLOCKED 규칙을 따른다.

## 6. PatchProposal state machine

`DRAFT → VALIDATING → PROPOSED → APPROVED|REJECTED|SUPERSEDED`.

- APPROVED는 immutable이며 SafetyContractVersion을 새로 생성한다.
- 같은 finding의 새 proposal 승인 시 이전 미승인 proposal은 SUPERSEDED.
- 승인 actor, comment, baseContractHash, resultingContractHash 필수.

## 7. UI action → API → state

| UI action | API | 전이/결과 |
|---|---|---|
| Analyze Release | `POST /releases/{id}:analyze` | DRAFT→ANALYZED |
| Run Baseline | `POST /test-runs` mode BASELINE | ANALYZED→TESTING |
| Generate Patch | `POST /findings/{id}/patch-proposals` | Finding→PATCH_PROPOSED |
| Approve & Retest | `POST /contract-versions/{id}:approve`, `POST /replays` | Release→VERIFYING |
| Run Verification | `POST /test-runs` HELD_OUT/REGRESSION | VERIFYING 유지 |
| Evaluate | `POST /releases/{id}/decision:evaluate` | →DECISION_PENDING |
| Confirm | `POST /releases/{id}/decision:confirm` | terminal |
| Reset Demo | `POST /demo:reset` | 새 demo namespace |

## 8. 오류·재진입 UX

- LLM 실패: curated seed로 계속할 수 있으면 degraded banner; 아니면 retry/resume.
- 취소: partial evidence와 completed case count 표시, decision 버튼 비활성.
- fingerprint mismatch: 기존 화면을 read-only로 전환하고 revalidation diff로 이동.
- SSE 끊김: 자동 reconnect 후 polling fallback; Run은 server-side 계속된다.
