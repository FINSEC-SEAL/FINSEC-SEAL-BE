# Agent Release Manifest Specification

## 1. 목적과 lifecycle

Manifest는 “무엇을 시험했는가”의 immutable 입력이다. `DRAFT`에서만 교체 가능하며 analyze 이후 변경은 새 AgentRelease를 만든다. 원문과 derived artifact/hash를 모두 저장한다.

## 2. Top-level schema

JSON Schema draft 2020-12 수준으로 다음을 요구한다. `additionalProperties=false`가 기본이다.

| 경로 | 타입/필수 | 규칙 |
|---|---|---|
| `schemaVersion` | string/필수 | `1.0` |
| `agent.id` | string/필수 | stable business key |
| `agent.name` | string/필수 | 1~100자 |
| `release.version` | semver/필수 | Agent 내 unique |
| `businessPurpose.code` | enum/필수 | `LOAN_DOCUMENT_COMPLETENESS_REVIEW` |
| `businessPurpose.description` | string/필수 | 승인/거절 아님을 명시 |
| `model.provider` | string/필수 | adapter key |
| `model.name` | string/필수 | exact provider model id |
| `model.parameters` | object/필수 | temperature, topP, maxTokens, seed? |
| `systemPrompt.text` | string/필수 | 1~100,000 UTF-8 chars |
| `systemPrompt.declaredSha256` | digest/선택 | server recompute와 일치해야 함 |
| `tools[]` | array/필수 | 1~50, unique tool name |
| `ragSources[]` | array/필수 | 없으면 `[]` |
| `networkRequirements` | object/필수 | P0 provider만; Agent tool egress 별도 |
| `businessWorkflow` | object/필수 | stages/current context source |
| `humanApprovalBoundaries[]` | array/필수 | LoanDecision actions 필수 |
| `runtimeContextRequirements[]` | array/필수 | case/applicant/stage/doc ids |
| `safetyContractRef` | object/조건 | 검증 cycle에서는 approved version |

## 3. Canonical example

```json
{
  "schemaVersion": "1.0",
  "agent": {"id": "loan-document-review-agent", "name": "대출서류 완전성 검토 Agent"},
  "release": {"version": "1.0.0"},
  "businessPurpose": {
    "code": "LOAN_DOCUMENT_COMPLETENESS_REVIEW",
    "description": "현재 Case의 제출서류 누락을 식별해 사람의 검토를 지원하며 대출 의사결정을 수행하지 않는다"
  },
  "model": {
    "provider": "openai-compatible",
    "name": "configured-model-id",
    "parameters": {"temperature": 0, "topP": 1, "maxTokens": 2048, "seed": 42}
  },
  "systemPrompt": {"text": "...", "declaredSha256": "sha256:..."},
  "tools": [
    {
      "name": "CUSTOMER_DATA_READ",
      "version": "1.0.0",
      "operation": "READ",
      "description": "Read explicitly requested synthetic customer fields",
      "inputSchema": {"type": "object", "properties": {"customerIds": {"type": "array"}, "fields": {"type": "array"}}, "required": ["customerIds", "fields"], "additionalProperties": false},
      "trustLevel": "TRUSTED_INTERNAL",
      "dataClassifications": ["NORMAL", "PII", "SENSITIVE_PII", "FINANCIAL", "CREDIT"]
    }
  ],
  "ragSources": [{"sourceId": "loan-policy", "version": "2026-demo-1", "trustLevel": "TRUSTED_INTERNAL", "retrievalConfig": {"topK": 3}}],
  "networkRequirements": {"modelProvider": true, "agentExternalEgress": false, "allowedHosts": ["configured-provider-host"]},
  "businessWorkflow": {"allowedStages": ["DOCUMENT_REVIEW"], "contextSourceTool": "CASE_CONTEXT_READ"},
  "humanApprovalBoundaries": [{"resource": "LoanDecision", "operations": ["APPROVED", "REJECTED"], "mode": "HUMAN_ONLY"}],
  "runtimeContextRequirements": ["caseId", "currentApplicantId", "workflowStage", "allowedDocumentIds"]
}
```

예시는 Tool 1개만 축약한 것이다. 실제 P0 manifest는 `05`의 7개 catalog를 모두 선언한다.

## 4. Tool item semantics

각 Tool은 `name`, `version`, `operation`, `description`, `inputSchema`, `outputSchema`, `trustLevel`, `riskLevel`, `dataClassifications`, `sideEffectType`, `adapterKey`를 가진다.

- `inputSchema/outputSchema`는 JSON Schema 2020-12 subset; remote `$ref`, regex lookaround, executable custom keyword 금지.
- `description`도 untrusted release input으로 validation/length 제한하고 fingerprint에 포함한다.
- `adapterKey`는 server allowlist에 존재해야 한다. Manifest로 arbitrary module/URL을 로드하지 않는다.
- `EXTERNAL_HTTP` adapterKey는 `mock_exfil_collector`만 허용한다.

## 5. Validation

### Schema validation

필수 필드, 타입, enum, 크기, unique, semver, digest 문법을 검사한다.

### Semantic validation

1. business purpose가 P0 template와 일치.
2. `CASE_CONTEXT_READ`, `DOCUMENT_READER`, `CUSTOMER_DATA_READ`, `LOAN_POLICY_SEARCH`, `REVIEW_NOTE_WRITE` 존재.
3. Demo attack을 위해 `LOAN_DECISION_UPDATE`, `EXTERNAL_HTTP`는 catalog에 존재할 수 있으나 normal allowed tool로 선언하지 않음.
4. LoanDecision human boundary 존재.
5. agentExternalEgress=false.
6. trusted RAG source version/digest 존재.
7. declared digest와 recompute digest 일치.

Issue schema: `{path,code,severity(ERROR|WARNING),message,evidence}`. ERROR가 있으면 analyze 금지.

## 6. Canonicalization/hashing

1. UTF-8 NFC normalization(문자열 내용은 공백 보존, line ending은 LF).
2. JSON number/keys는 RFC 8785 JSON Canonicalization Scheme.
3. list 의미가 set인 tools/ragSources/human boundaries는 stable key로 정렬; prompt text와 workflow ordered steps는 순서 보존.
4. 각 artifact SHA-256: `sha256:<lowerhex>`.
5. `agentArtifactFingerprint` input은 model/prompt/tool/RAG/business purpose/workflow/runtime context digest를 포함한다.
6. Final `releaseFingerprint` input은 agent artifact fingerprint와 approved Safety Contract hash를 결합한다.

```json
{
  "fingerprintVersion": "finsec-agent-artifact/v1",
  "businessPurposeHash": "...",
  "modelHash": "...",
  "systemPromptHash": "...",
  "toolSetHash": "...",
  "ragConfigHash": "...",
  "workflowHash": "...",
  "runtimeContextHash": "..."
}
```

위 canonical object의 SHA-256이 agent artifact fingerprint다. Final release fingerprint는 `{"fingerprintVersion":"finsec-release/v1","agentArtifactFingerprint":"...","safetyContractHash":"...or null"}`의 canonical SHA-256이다. prompt 원문은 application envelope encryption으로 저장하고 접근 audit를 남긴다.

## 7. Revalidation trigger/diff

Model/provider/parameters, system prompt, Tool add/remove/schema/description/trust/classification, RAG source/version/config, Safety Contract, business purpose/workflow/runtime context 변경은 terminal decision 이후 `PASS|REVIEW|BLOCKED → NEEDS_REVALIDATION`을 만든다. 최초 baseline finding 뒤 같은 validation cycle에서 candidate를 승인하는 것은 planned `null → approved contract` transition이며 Release를 VERIFYING으로 보내고 baseline evidence는 agent artifact fingerprint 일치로 재사용한다. Diff는 component, JSON pointer, old/new digest, redacted summary를 제공한다.

다음은 trigger가 아니다: display name, UI note, report regeneration, reviewer display label. Manual invalidate는 항상 가능하다.

## 8. Integrity failures

- 저장 artifact를 재해시해 fingerprint가 다르면 release를 `NEEDS_REVALIDATION`, security event `RELEASE_ARTIFACT_INTEGRITY_FAILURE`로 기록하고 실행 금지.
- provider가 model alias를 실제 다른 model로 resolve하면 provider response의 resolved model id를 Run에 기록하고 manifest id와 다르면 결과를 REVIEW/비교 불가 처리한다.
