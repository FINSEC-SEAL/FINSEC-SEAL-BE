# Functional Specification

공통 실패 형식은 `application/problem+json`이며 `code`, `message`, `traceId`, `details`, `retryable`을 포함한다. 모든 mutation은 audit event와 idempotency를 적용한다.

## FS-01 Agent/Release 등록 및 분석

- **Actor/Trigger:** Agent Developer가 manifest 제출.
- **Precondition:** logical `AGENT_DEVELOPER`; manifest schemaVersion 지원.
- **Main:** schema 검증 → artifact canonicalization/hash → tool/RAG 참조 검증 → fingerprint 계산 → Release `DRAFT` 생성 → analyze 시 `ANALYZED`.
- **Alternative:** 동일 fingerprint release가 있으면 기존 release link를 반환하고 새 생성 여부를 확인.
- **Failure:** schema/hash 불일치 `422 MANIFEST_INVALID`; unsupported provider `422 PROVIDER_UNSUPPORTED`.
- **Input/Output:** manifest JSON → release, artifact digests, validation issues, diff.
- **Acceptance:** model/prompt/tool description/schema/RAG/business purpose/contract 중 하나를 바꾸면 digest가 달라지고 이전 terminal release는 `NEEDS_REVALIDATION` effective status가 된다.

## FS-02 Demo environment load/reset

- **Actor/Trigger:** 평가자/Reviewer가 Load 또는 Reset.
- **Precondition:** active destructive Demo run 없음; demo tenant만.
- **Main:** fixtureVersion 조회 → immutable seed에서 namespace clone → digest 검증 → active demo pointer 교체.
- **Alternative:** reset 요청이 중복이면 같은 operation 결과 반환.
- **Failure:** active run `409 DEMO_RUN_ACTIVE`; digest mismatch `500 FIXTURE_INTEGRITY_FAILURE`.
- **Input/Output:** fixtureVersion → namespaceId, fixtureDigest, readyAt.
- **Acceptance:** 10회 reset 후 entity count와 digest가 동일하며 다른 Run namespace는 영향을 받지 않는다.

## FS-03 Test generation

- **Actor/Trigger:** Developer가 Generate Tests.
- **Precondition:** Release `ANALYZED`; templates 활성.
- **Main:** template 선택 → AttackIntent 고정 → LLM variant 생성 → JSON schema/length/tool/category allowlist 검증 → partition별 TestCase 저장.
- **Alternative:** provider 실패 시 curated seed만으로 suite를 만들고 `generationDegraded=true`.
- **Failure:** 모든 variant invalid면 `FAILED LLM_OUTPUT_INVALID`; retry 2회 후 종료.
- **Input/Output:** suite config, categories, mutationCount → TestSuite summary. Held-out payload는 응답에 포함하지 않는다.
- **Acceptance:** LLM이 category/severity/oracle/invariant를 변경할 수 없고 parentSeedId가 항상 존재한다.

## FS-04 Baseline test 실행

- **Actor/Trigger:** Reviewer가 Run Baseline.
- **Precondition:** Release analyzed, no active run, suite valid.
- **Main:** snapshot clone → Run `RUNNING` → 각 TestCaseRun/trial 생성 → Agent 실행 → gateway `BASELINE_TOOL_ALLOW` 관찰 → Mock API actual effect → oracle → finding/metrics → terminal status.
- **Alternative:** 개별 case 실패는 다른 case 계속; fail-fast는 fixture integrity/secret leak만.
- **Failure:** provider timeout은 case `ERROR`; 20% 초과 operational error면 run `FAILED`.
- **Input/Output:** releaseId, suiteId, trial policy → runId/SSE/results.
- **Acceptance:** 대표 3개 공격에서 API response/state/collector evidence가 oracle input으로 저장된다.

## FS-05 Finding 조회와 Patch Proposal

- **Actor/Trigger:** Security Reviewer가 finding 상세/Generate Proposal.
- **Precondition:** finding `OPEN|TRIAGED`; held-out source가 아님.
- **Main:** evidence pack + manifest + approved financial template를 LLM에 제공 → root cause/violated invariant/rule/impact/policy diff 후보 → deterministic patch validator → `PROPOSED`.
- **Alternative:** 규칙이 기존 contract와 중복이면 `NO_CHANGE_NEEDED` suggestion.
- **Failure:** held-out reference 감지 `403 HELD_OUT_ACCESS_DENIED`; invalid patch `422 PATCH_INVALID`.
- **Acceptance:** proposal에는 normal workflow 영향과 rollback이 포함되고 production/runtime policy는 변경되지 않는다.

## FS-06 Contract candidate/validation/approval

- **Actor/Trigger:** Reviewer가 candidate 생성 또는 Approve.
- **Precondition:** candidate 생성은 analyzed release; 승인은 `AI_SECURITY_REVIEWER`, self-approval은 MVP 허용하되 audit에 `demoMode=true`.
- **Main:** LLM candidate → schema/business template validator → reviewer diff 확인 → approval comment → immutable ContractVersion `APPROVED` → release verification contract로 연결.
- **Alternative:** `REJECTED` 후 새 version 생성; 승인 version 수정 금지.
- **Failure:** minimum permission 누락 또는 maximum 초과 `422 CONTRACT_VALIDATION_FAILED`.
- **Acceptance:** 승인을 통하지 않은 version은 gateway ENFORCE 모드에서 선택할 수 없다.

## FS-07 Replay

- **Actor/Trigger:** Reviewer가 finding의 attack replay.
- **Precondition:** approved contract; original AttackCase와 baseline TestCaseRun 존재.
- **Main:** original `test_case_id`, `variant_hash`, `trial_index`, fixtureVersion을 참조해 새 namespace → policy만 ENFORCE로 변경 → 실행/oracle → comparison 생성.
- **Alternative:** original model unavailable 시 `REVIEW` 표시; 다른 model로 replay 금지.
- **Failure:** agentArtifactFingerprint mismatch `409 RELEASE_CHANGED`; snapshot clone 실패. approved policy hash 차이는 replay의 의도된 독립변수다.
- **Acceptance:** before/after는 같은 attack identity를 공유하며 policy decision/API call/state diff를 필드별 비교한다.

## FS-08 Held-out 및 Regression

- **Actor/Trigger:** Reviewer가 Verify Release.
- **Precondition:** approved contract/replay 완료.
- **Main:** held-out repository가 opaque ids를 run worker에 제공 → trials → oracle; 이어 normal suite → structured/state evaluator → metrics.
- **Alternative:** held-out generation 없이 curated held-out만 사용 가능.
- **Failure:** patch generator access 시 security audit + run abort; operational error threshold 초과 시 decision 불가.
- **Acceptance:** patch 관련 log/request에서 held-out payload hash가 발견되지 않으며 normal false block이 계산된다.

## FS-09 Release Decision

- **Actor/Trigger:** Governance Reviewer가 Evaluate/Confirm.
- **Precondition:** required suites terminal, metric denominators 충분, artifact/contract fingerprint current.
- **Main:** deterministic gate rules → proposed PASS/REVIEW/BLOCKED → reviewer confirms; override는 PASS 상향 금지, PASS→REVIEW/BLOCKED 하향만 허용.
- **Alternative:** operational error/표본 부족이면 REVIEW.
- **Failure:** critical held-out success가 있는데 PASS 요청 `409 GATE_CONSTRAINT_VIOLATION`.
- **Acceptance:** decision에 rule version, inputs, numerator/denominator, reviewer/audit id가 저장된다.

## FS-10 Attestation/export

- **Actor/Trigger:** Governance Reviewer/평가자가 Report 열기.
- **Precondition:** terminal decision 존재.
- **Main:** immutable decision snapshot + artifacts/metrics/findings/approvals로 JSON/HTML 생성 → content hash 저장.
- **Alternative:** current release가 revalidation이면 과거 report는 유지하되 `STALE/NEEDS_REVALIDATION` banner 표시.
- **Failure:** evidence 누락 `409 EVIDENCE_INCOMPLETE`.
- **Acceptance:** 한·영 disclaimer, baseline/SEAL, remaining findings, revalidation triggers가 필수다.

## FS-11 Event streaming/status/cancel

- **Actor/Trigger:** UI가 SSE 연결/사용자가 Cancel.
- **Precondition:** run read 권한.
- **Main:** `Last-Event-ID` 이후 event replay → live subscribe → heartbeat 15초; cancel token set → safe checkpoint 종료.
- **Alternative:** SSE 불가 시 2초 polling.
- **Failure:** expired event retention `410 STREAM_CURSOR_EXPIRED` 후 current snapshot 재조회.
- **Acceptance:** reconnect 시 sequence 중복은 가능하나 누락이 없고 UI는 eventId로 dedupe한다.

## FS-12 Release invalidation

- **Actor/Trigger:** 새 release artifact/contract 연결 또는 reviewer manual invalidate.
- **Precondition:** terminal decision 존재.
- **Main:** terminal decision의 stored agent/release fingerprints와 recomputed fingerprints 비교 → trigger 목록/diff 저장 → effective status `NEEDS_REVALIDATION`. 최초 contract 승인은 같은 validation cycle의 VERIFYING 전이로 기록하고 invalidation하지 않는다.
- **Alternative:** display metadata만 변경되면 무효화하지 않음.
- **Failure:** artifact 원문 누락 시 fail closed로 NEEDS_REVALIDATION.
- **Acceptance:** 과거 Attestation은 삭제하지 않고 invalidatedAt/reason을 표시한다.

## 공통 처리 규칙

- Retry: LLM/network adapter만 exponential backoff 1s/2s, 최대 2회; state-changing Tool은 자동 retry하지 않고 idempotency key로 명시 재시도.
- Timeout: LLM 45s, Tool 5s, TestCase 90s, Run 20분.
- Rate: demo session당 active run 1, test start 10/시간, report 30/시간.
- 비용: Run config의 maxCases/maxTrials/maxTokens/maxEstimatedCost를 넘기기 전 중단하고 `BUDGET_EXCEEDED`.
