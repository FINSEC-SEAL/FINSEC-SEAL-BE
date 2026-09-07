# REST / SSE API Specification

## 1. 공통 계약

- Base: `/api/v1`; JSON UTF-8; 시간 RFC 3339 UTC; id는 UUIDv7 문자열.
- 인증: 대회 Demo session cookie(`HttpOnly`, `Secure`, `SameSite=Lax`)와 logical role. mutation에는 CSRF token.
- Mutation header: `Idempotency-Key` 필수(1~128자). 같은 actor/path/key/body hash는 24시간 동일 응답, 다른 body는 `409 IDEMPOTENCY_CONFLICT`.
- 목록: `limit` 1~100(default 25), opaque `cursor`, 응답 `{items,nextCursor}`.
- 오류: RFC 9457형 `{type,title,status,code,detail,traceId,retryable,errors[]}`.
- Optimistic concurrency: Contract/Decision update에 `If-Match: "<resourceHash>"`.

## 2. Endpoint catalog

### Agents

| Method/Path | 설명 | Request → Response | 검증/오류 | 상태/Idempotency |
|---|---|---|---|---|
| `POST /agents` | Agent 생성 | `{agentKey,name,purposeSummary}` → `201 Agent` | key regex/unique; 409 | 생성; 필수 |
| `GET /agents` | 목록 | filters → page | role/workspace | read |
| `GET /agents/{agentId}` | 상세/최신 release | — → AgentDetail | 404 | read |

### Releases

| Method/Path | 설명 | Request → Response | 검증/오류 | 상태/Idempotency |
|---|---|---|---|---|
| `POST /agents/{id}/releases` | manifest로 release 생성 | `AgentReleaseManifest` → `201 ReleaseDetail` | schema/hash/ref; 422 | DRAFT; 필수 |
| `GET /releases/{id}` | release/tabs summary | — → detail | 404 | read |
| `GET /releases/{id}/diff?against=` | artifact semantic diff | — → fields/old/new hashes | 같은 agent; 422 | read |
| `GET /releases/{id}/fingerprint` | 구성 digest | — → fingerprint/components | artifact 접근 redaction | read |
| `POST /releases/{id}:validate` | schema/semantic validation | `{}` → ValidationResult | DRAFT; 409 | 상태 불변; 필수 |
| `POST /releases/{id}:analyze` | 분석/fingerprint 확정 | `{testSuiteVersion?}` → Operation | valid manifest; 422 | DRAFT→ANALYZED; 필수 |

### Test execution

| Method/Path | 설명 | Request → Response | 검증/오류 | 상태/Idempotency |
|---|---|---|---|---|
| `POST /test-runs` | mode별 run 시작 | `{releaseId,suiteId,mode,contractVersionId?,caseIds?,trialOverride?}` → `202 {runId,statusUrl,streamUrl}` | lifecycle/active/budget; 409/422 | Release TESTING/VERIFYING; 필수 |
| `GET /test-runs/{id}` | status/progress | — → TestRunDetail | 404 | read |
| `POST /test-runs/{id}:cancel` | cooperative cancel | `{reason}` → `202` | terminal이면 409 | →CANCELLING; 필수 |
| `GET /test-runs/{id}/results` | case/oracle/metrics | filters → page+summary | held-out payload 제거 | read |
| `GET /test-runs/{id}/events` | SSE | `Last-Event-ID` → stream | cursor 410 | read/reconnect |

`mode`별 guard: BASELINE은 contract null, SEAL_REPLAY/HELD_OUT/REGRESSION은 APPROVED contract 필수. HELD_OUT은 caseIds를 외부에서 지정할 수 없다.

### Findings/Patch

| Method/Path | 설명 | Request → Response | 검증/오류 | 상태/Idempotency |
|---|---|---|---|---|
| `GET /findings` | release/category/status 목록 | query → page | workspace | read |
| `GET /findings/{id}` | oracle/evidence/trace 상세 | — → FindingDetail | evidence redaction | read |
| `POST /findings/{id}:triage` | reviewer 확인 | `{comment}` → Finding | role | OPEN→TRIAGED; 필수 |
| `POST /findings/{id}/patch-proposals` | proposal 생성 | `{baseContractVersionId}` → `202 Operation` | held-out 금지; 403 | →PATCH_PROPOSED; 필수 |
| `GET /patch-proposals/{id}` | diff/validation/impact | — → Proposal | 404 | read |
| `POST /patch-proposals/{id}:reject` | 기각 | `{comment}` → Proposal | role/hash | REJECTED; 필수 |

### Contracts

| Method/Path | 설명 | Request → Response | 검증/오류 | 상태/Idempotency |
|---|---|---|---|---|
| `POST /releases/{id}/contracts:generate` | hybrid candidate | `{templateKey}` → `202` | release analyzed | CANDIDATE; 필수 |
| `POST /contract-versions/{id}:validate` | deterministic validation | `{}` → ValidationResult | schema/template | →VALIDATED/유지; 필수 |
| `POST /contract-versions/{id}:approve` | reviewer 승인 | `{comment,patchProposalId?}` → ApprovedVersion | If-Match/role | →APPROVED; 필수 |
| `GET /contracts/{id}/versions` | version history | — → list | 404 | read |
| `GET /contract-versions/{id}` | policy/diff | — → ContractVersion | role/redaction | read |

### Replay

| Method/Path | 설명 | Request → Response | 검증/오류 | 상태/Idempotency |
|---|---|---|---|---|
| `POST /replays` | 특정 attack 동일조건 replay | `{findingId,baselineCaseRunId,contractVersionId}` → `202 {runId}` | same release/fingerprint; 409 | VERIFYING; 필수 |
| `GET /replays/{id}/comparison` | before/after | — → decisions/API/state/oracle diff | pair complete | read |

### Decision/Report

| Method/Path | 설명 | Request → Response | 검증/오류 | 상태/Idempotency |
|---|---|---|---|---|
| `POST /releases/{id}/decision:evaluate` | deterministic gate | `{}` → DecisionProposal | required evidence; 409 | →DECISION_PENDING; 필수 |
| `POST /releases/{id}/decision:confirm` | 확정 | `{decision,comment}` → Decision | 상향 override 금지/If-Match | terminal; 필수 |
| `POST /releases/{id}:invalidate` | manual invalidation | `{reason}` → Release | role | terminal→NEEDS_REVALIDATION; 필수 |
| `GET /releases/{id}/attestation` | canonical report JSON | — → Attestation | decision required | read |
| `GET /releases/{id}/evidence-export?format=json|html` | export | — → download | html/json P0 | read |

### Demo

| Method/Path | 설명 | Request → Response | 검증/오류 | 상태/Idempotency |
|---|---|---|---|---|
| `POST /demo:load` | seed workspace/agent/release | `{scenarioSet:"GOLDEN"}` → DemoContext | demo mode only | 필수 |
| `POST /demo:reset` | fixture/derived demo data reset | `{fixtureVersion}` → `202 Operation` | active run 409 | 필수 |
| `GET /demo/status` | readiness | — → services/fixture/release | — | read |

## 3. 중요 request/response schema

### Start TestRun

```json
{
  "releaseId": "uuid",
  "suiteId": "uuid",
  "mode": "BASELINE",
  "contractVersionId": null,
  "trialOverride": {"critical": 3, "default": 1},
  "budget": {"maxCases": 50, "maxTokens": 200000, "maxEstimatedUsd": 10}
}
```

Response `202`: `{runId,status:"QUEUED",statusUrl,streamUrl,requestId}`.

### Policy deny tool result

Gateway 내부 결과를 Agent에는 Tool error로, API/UI에는 다음과 같이 표현한다.

```json
{
  "allowed": false,
  "httpEquivalent": 403,
  "reasonCode": "CUSTOMER_SCOPE_VIOLATION",
  "failedCheck": "OBJECT_SCOPE",
  "policyVersion": 2,
  "inputDigest": "sha256:...",
  "message": "Requested customer is outside current applicant scope"
}
```

### Before/After comparison

`baseline`와 `seal` 각각 `testCaseRunId`, `agentArtifactFingerprint`, `releaseFingerprint`, `contractHash`, `variantHash`, `policyDecision`, `apiInvoked`, `apiStatus`, `stateDelta`, `oracleOutcome`, `evidenceDigest`를 포함한다. `comparability`는 agentArtifact/fixture/model/variant 일치와 `expectedPolicyDifference=true`를 요구한다. 전체 releaseFingerprint는 Contract hash 때문에 달라야 정상이다. 조건 하나라도 실패하면 “controlled comparison” 라벨을 붙이지 않는다.

## 4. SSE contract

Headers: `Content-Type: text/event-stream`, `Cache-Control: no-cache`, heartbeat 15초.

```text
id: 142
event: run.progress
data: {"schemaVersion":"1.0","runId":"...","sequence":142,"occurredAt":"...","phase":"BASELINE","status":"RUNNING","completed":6,"total":20,"latestEventType":"ORACLE_EVALUATED","traceId":"..."}
```

Event names: `run.status`, `run.progress`, `case.status`, `trace.event`, `finding.created`, `run.metric`, `run.completed`, `heartbeat`. `trace.event`의 input/output은 redacted view만 포함한다. Server는 마지막 10,000개/Run 또는 7일을 stream replay 대상으로 보존하고 canonical events는 DB retention에 따른다.

## 5. Validation rules

- JSON body 최대 1MB; manifest 2MB; 합성 document text 256KB. P1 binary PDF는 별도 upload.
- unknown fields는 spec version별 기본 reject. enum 대소문자 정확 일치.
- URL은 EXTERNAL_HTTP에서 label/allowlisted mock URL만 허용하며 resolver/network call을 하지 않는다.
- caseIds/customerIds는 형식뿐 아니라 namespace/current context에서 검사한다.
- client가 `currentApplicantId`, `humanApprovalPresent`, `toolTrust`를 보낼 수 없으며 server context만 사용한다.

## 6. Error codes

`MANIFEST_INVALID`, `RELEASE_CHANGED`, `INVALID_STATE_TRANSITION`, `RUN_ALREADY_ACTIVE`, `BUDGET_EXCEEDED`, `PROVIDER_TIMEOUT`, `LLM_OUTPUT_INVALID`, `FIXTURE_INTEGRITY_FAILURE`, `CONTRACT_VALIDATION_FAILED`, `HELD_OUT_ACCESS_DENIED`, `GATE_CONSTRAINT_VIOLATION`, `EVIDENCE_INCOMPLETE`, `STREAM_CURSOR_EXPIRED`, `IDEMPOTENCY_CONFLICT`, plus Policy reason codes from `12/16`.

## 7. A 계약 저장 API 구현 연결 (2026-09-07)

위 Contracts 표의 원 경로를 유지한다. 현재 원 명세의 상세·검증·승인과 계약 UUID별 페이지 이력은
`ContractSpecificationController`가 같은 A 저장 서비스에 연결한다. 공통 API envelope의 data에
검증 응답은 `status,issues,versionId,state,resourceHash,policyHash,validationProof`, 이력 응답은
`{items,nextCursor}`를 제공한다. 버전 상세의 `contractId`는 DB 계약 UUID이며 정책 안의 문자열 contractId와 구분한다.

검토자 세션은 `/api/v1/reviewer-session`에서 서버 설정 자격으로 발급하며 HttpOnly/Secure/SameSite=Lax 쿠키와 mutation CSRF를 검증한다.
기존 키 방식은 Cookie 없는 서버 간/로컬 호출의 추가 인증 수단으로 유지한다. 공개 방문자별 guest/demo workspace 발급 전체와 혼동하지 않는다.

추가 후보 저장·현재 승인본 조회·출처 필터 및 이전 `/platform/contracts` 경로의 호환 여부,
선택적 patchProposalId의 승인 연결은 [A 계약 API 인수인계](../A_CONTRACT_INTEGRATION_HANDOFF.md)에 명시한다.
`contracts:generate`와 Finding의 비동기 patch 생성은 B/C의 생성 연결 작업이며 이 저장 API와 별개다.
