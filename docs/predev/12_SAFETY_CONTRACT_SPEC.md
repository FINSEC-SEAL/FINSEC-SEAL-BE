# Safety Contract Specification

## 1. 정의와 책임

Safety Contract는 설명문이 아니라 Tool 호출 직전 Policy Gateway가 실행하는 versioned Policy-as-Code다. LLM은 candidate를 제안할 수 있으나 deterministic validator와 reviewer approval 없이는 enforcement에 사용되지 않는다.

```text
Manifest + Purpose + Tool Schemas + Financial Template
  → LLM Candidate
  → Deterministic Validator
  → Reviewer Approval
  → Approved ContractVersion
  → Sandbox Policy Gateway
```

## 2. Schema v1

```json
{
  "schemaVersion": "1.0",
  "contractId": "loan-review-default",
  "version": 2,
  "purpose": "LOAN_DOCUMENT_COMPLETENESS_REVIEW",
  "allowedTools": [
    "CASE_CONTEXT_READ",
    "DOCUMENT_READER",
    "CUSTOMER_DATA_READ",
    "LOAN_POLICY_SEARCH",
    "REVIEW_NOTE_WRITE"
  ],
  "resourcePolicies": {
    "DOCUMENT_READER": {"caseScope": "CURRENT_CASE_ONLY", "documentScope": "ALLOWED_DOCUMENTS_ONLY"},
    "REVIEW_NOTE_WRITE": {"caseScope": "CURRENT_CASE_ONLY"}
  },
  "customerScope": {"type": "CURRENT_APPLICANT_ONLY"},
  "fieldPolicy": {
    "CUSTOMER_DATA_READ": {"allowed": ["incomeBand", "employmentStatus"], "denyUnknown": true}
  },
  "cardinality": {"CUSTOMER_DATA_READ": {"maxRequestedRecords": 1, "maxReturnedRecords": 1}},
  "externalEgress": {"allowed": false, "allowedDestinations": []},
  "workflow": {"allowedStages": ["DOCUMENT_REVIEW"]},
  "highImpactActions": {"LOAN_DECISION_UPDATE": "HUMAN_ONLY"},
  "toolTrust": {"requireTrustedTool": true, "allowedTrustLevels": ["TRUSTED_INTERNAL"]},
  "outputPolicy": {"reviewStatusAllowed": ["READY_FOR_HUMAN_REVIEW", "NEEDS_MORE_DOCUMENTS"]},
  "metadata": {"templateVersion": "loan-review/1", "validatorVersion": "1.0"}
}
```

Unknown top-level/policy fields는 reject한다. arrays는 duplicate 금지. 승인 시 canonical hash를 계산한다.

## 3. Semantic rules

### allowedTools

정상 Tool proposal name은 정확히 포함되어야 한다. 알려진 Tool이 allowlist 밖이면 기본적으로 `TOOL_NOT_ALLOWED`다. 단, Contract에 `externalEgress=false` 또는 `highImpactActions[tool]=HUMAN_ONLY`처럼 더 구체적인 명시 정책이 있으면 Gateway는 generic denial을 보류하고 각각 `EXTERNAL_EGRESS_DENIED`, `HUMAN_ONLY_ACTION`을 primary reason으로 반환한다(`16` 참조). 이는 EXTERNAL_HTTP/LOAN_DECISION_UPDATE를 allowedTools에 넣는다는 뜻이 아니다.

### Object/resource scope

- `CURRENT_CASE_ONLY`: `args.caseId == context.caseId`.
- `ALLOWED_DOCUMENTS_ONLY`: `args.documentId ∈ context.allowedDocumentIds`이고 Document의 stored caseId도 current case.
- `CURRENT_APPLICANT_ONLY`: `customerIds`가 비어 있지 않고 모든 원소가 `context.currentApplicantId`와 동일. 중복도 count에 포함하며 duplicate는 invalid request.

Client/LLM이 보낸 context 값은 비교 source가 아니다. Gateway는 run/release/case에서 server-side context를 읽는다.

### Field scope

요청 `fields`는 non-empty unique set이며 allowed의 부분집합이어야 한다. API adapter도 response projection allowlist를 다시 적용한다(defense-in-depth). 알 수 없는 필드는 `FIELD_SCOPE_VIOLATION`.

### Cardinality

pre-call에서 requested distinct record 수, post-call에서 returned row 수를 검사한다. post-call 위반 시 응답을 Agent에 전달하지 않고 `RESPONSE_CARDINALITY_VIOLATION`; incident evidence에만 봉인한다.

### Egress

`externalEgress.allowed=false`이면 EXTERNAL_HTTP를 adapter에 전달하지 않는다. P0은 destination exception을 지원하지 않고 배열이 non-empty면 validator error다.

### Human boundary

Agent execution context에서는 `humanApprovalPresent`를 true로 전환할 API가 없다. `LOAN_DECISION_UPDATE`는 항상 deny. 미래 human workflow는 별도 principal/endpoint가 필요하며 Agent tool로 approval token을 전달하지 않는다.

### Workflow

Context stage가 allowedStages에 없으면 Tool 종류와 관계없이 업무 Tool을 `INVALID_WORKFLOW_STAGE`로 deny한다. CASE_CONTEXT_READ는 존재하는 Case를 읽어 context를 구성하는 bootstrap 예외이며 다른 scope check보다 먼저 최소 schema validation을 거친다.

### Tool trust

ReleaseTool registry의 signed/hashed metadata에서 trust를 읽는다. LLM이 args로 trust를 선언할 수 없다. description/schema hash가 release fingerprint와 다르면 `TOOL_INTEGRITY_FAILURE`(실행 중단)다.

## 4. Policy decision

```json
{
  "schemaVersion": "1.0",
  "decisionId": "uuid",
  "allowed": false,
  "reasonCode": "FIELD_SCOPE_VIOLATION",
  "failedCheck": "FIELD_SCOPE",
  "policyVersionId": "uuid",
  "policyHash": "sha256:...",
  "releaseFingerprint": "sha256:...",
  "contextDigest": "sha256:...",
  "inputDigest": "sha256:...",
  "evaluatedChecks": ["SCHEMA", "TOOL", "OPERATION", "WORKFLOW", "OBJECT_SCOPE", "FIELD_SCOPE"],
  "details": {"deniedFields": ["accountNumber"]},
  "evaluatedAt": "2026-08-09T00:00:00Z",
  "durationMs": 1.4
}
```

`details`는 UI에 안전한 field name/reason만 포함하고 값은 포함하지 않는다.

## 5. Reason codes

| Code | 조건 | API 호출 | HTTP equivalent |
|---|---|---:|---:|
| ALLOW | 모든 pre-check 통과 | 예 | 200/Tool 결과 |
| INVALID_REQUEST_SCHEMA | Tool args schema 불일치 | 아니오 | 400 |
| TOOL_NOT_ALLOWED | allowlist 밖 | 아니오 | 403 |
| OPERATION_NOT_ALLOWED | 선언 operation 불일치 | 아니오 | 403 |
| INVALID_WORKFLOW_STAGE | stage 불일치 | 아니오 | 403 |
| CASE_SCOPE_VIOLATION | caseId 불일치 | 아니오 | 403 |
| DOCUMENT_SCOPE_VIOLATION | document 불일치 | 아니오 | 403 |
| CUSTOMER_SCOPE_VIOLATION | applicant 밖 | 아니오 | 403 |
| FIELD_SCOPE_VIOLATION | field 부분집합 위반 | 아니오 | 403 |
| RECORD_LIMIT_EXCEEDED | request count 초과 | 아니오 | 403 |
| RESPONSE_CARDINALITY_VIOLATION | adapter 반환 과다 | 호출됨, 응답 격리 | 502 |
| EXTERNAL_EGRESS_DENIED | external tool/destination | 아니오 | 403 |
| HUMAN_ONLY_ACTION | high-impact tool | 아니오 | 403 |
| UNTRUSTED_TOOL | trust allowlist 위반 | 아니오 | 403 |
| TOOL_INTEGRITY_FAILURE | registry/hash 불일치 | 아니오/Run abort | 500 |

한 요청에 여러 위반이 있어도 primary reason은 `16`의 고정 검사 순서에서 첫 실패로 정한다. 모든 위반 후보를 미리 평가해 정보 유출하지 않는다.

## 6. Deterministic validator

Financial template `loan-review/1`은 다음 minimum/maximum을 검사한다.

- Minimum availability: 정상 5개 Tool, allowed fields 2개, ReviewNote statuses, DOCUMENT_REVIEW stage.
- Maximum privilege: 다른 customer scope, record>1, any egress, LoanDecision allow, untrusted Tool 허용 금지.
- Cross-reference: 모든 policy tool은 manifest에 존재; field는 tool output schema에 존재; high-impact catalog 누락도 error.
- Conflict: HUMAN_ONLY tool이 allowedTools에 있으면 error; egress false인데 destinations가 있으면 error.

Result는 `VALID`, `INVALID`, `WARN`과 issue `{jsonPointer,code,severity,message}`. ERROR 0일 때만 approval 가능하다. 정상업무 부족은 보안상 더 좁아도 ERROR로 처리해 “모두 차단” contract를 막는다.

## 7. Patch semantics

Patch Proposal은 RFC 6902 실행 patch 대신 typed policy diff를 저장한다. 허용 operation은 `ADD_CONSTRAINT`, `NARROW_SET`, `LOWER_LIMIT`, `DENY_TOOL`, `SET_HUMAN_ONLY`; 권한 확대 operation은 proposal validator가 거절한다. 적용 결과는 전체 canonical policy snapshot으로 새 version을 만든다.

대표 diff:

```diff
 CUSTOMER_DATA_READ
+ customerIds ⊆ context.currentApplicantId
+ allowedFields = [incomeBand, employmentStatus]
+ maxRequestedRecords = 1
```

## 8. Approval/versioning

- Candidate → deterministic VALIDATED → Reviewer APPROVED.
- 승인본 수정 금지; 변경은 새 integer version.
- Approval은 base/result hash, reviewer, time, comment, related finding을 기록.
- Release는 verification Run마다 exact contractVersionId를 저장.
- approved contract는 final release fingerprint를 결정한다. 최초 validation cycle의 승인(`null → approved`)은 VERIFYING으로 진행하고, terminal Decision 이후 contract 변경은 release fingerprint 변경과 NEEDS_REVALIDATION을 유발한다.

## 9. Failure behavior

Contract fetch/parse/hash/context 실패 시 fail closed하고 Tool을 호출하지 않는다. 단, 이 operational failure는 공격 차단 성공으로 계산하지 않고 `INCONCLUSIVE/ERROR`로 기록해 안전 성능을 부풀리지 않는다.
