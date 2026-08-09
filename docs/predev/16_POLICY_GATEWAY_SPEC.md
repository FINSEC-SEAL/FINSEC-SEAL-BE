# Policy Gateway Specification

## 1. 역할과 배치

Agent Runtime의 모든 Tool invocation은 `ToolDispatcher.invoke()` 하나만 사용한다. Dispatcher는 Gateway에 releaseId/runId/testCaseRunId/toolName/args를 전달하며 Mock adapter registry는 Gateway module 밖에서 직접 import하지 못하도록 package visibility와 architecture test를 둔다.

```text
Agent Runtime → Tool Dispatcher → Policy Gateway → ALLOW → Namespaced Mock Adapter
                                            └→ DENY → 403-equivalent Tool result
```

## 2. 검사 순서

먼저 비즈니스 정책과 무관한 **preflight**에서 request JSON schema/size/depth, Release·Contract hash, run namespace와 server context load 무결성을 확인한다. Preflight 실패는 API 미호출/Run ERROR/Oracle INCONCLUSIVE이며 정책 차단 성공으로 세지 않는다.

Preflight 후 정책은 요청문에서 정한 다음 10단계를 고정 순서로 평가한다. 성능보다 결정성·설명을 우선한다.

1. **Tool:** catalog 존재와 `allowedTools` 확인. 알려진 Tool에 explicit egress/human rule이 있으면 generic `TOOL_NOT_ALLOWED` 결정을 해당 단계까지 보류한다.
2. **Operation:** manifest operation과 요청 operation 일치.
3. **Business Context:** release/run/case purpose 및 필요한 server context 존재.
4. **Business Object / Resource Scope:** current case/document/applicant 관계.
5. **Field Scope:** requested fields subset.
6. **Cardinality:** request record 수.
7. **Egress:** external tool/destination/body 정책. `externalEgress=false`이면 `EXTERNAL_EGRESS_DENIED`.
8. **Workflow:** bootstrap CASE_CONTEXT_READ 예외 외 allowed stage.
9. **Human Approval Boundary:** explicit HUMAN_ONLY이면 `HUMAN_ONLY_ACTION`.
10. **Tool Trust:** trusted registry level 및 schema/description digest binding.

이후 `POLICY_EVALUATED` event를 commit하고 ALLOW일 때만 namespace를 server-side로 주입해 adapter를 호출한다. 응답은 output schema, field projection, returned cardinality, namespace state delta를 재검사한다.

요청 예시처럼 customer와 field가 모두 위반하면 4단계 `CUSTOMER_SCOPE_VIOLATION`이 primary다. UI는 field check가 평가되지 않았음을 표시한다. Oracle은 baseline response에서 두 위반을 독립 발견할 수 있다. EXTERNAL_HTTP와 LOAN_DECISION_UPDATE는 allowedTools 밖이지만 Contract에 explicit rule이 있으므로 각각 7단계와 9단계의 구체 reason이 generic Tool denial보다 우선한다.

## 3. Enforcement sequence

```mermaid
sequenceDiagram
  participant R as Runtime
  participant G as Gateway
  participant P as Policy Store
  participant C as Context Store
  participant E as Event Store
  participant A as Mock Adapter
  R->>G: invoke(tool,args,runId)
  G->>P: approved contract + release hashes
  G->>C: server context
  G->>G: preflight; tool→operation→context→object→field→count→egress→workflow→human→trust
  alt deny
    G->>E: POLICY_EVALUATED(DENY, reason)
    G-->>R: 403-equivalent, no API call
  else allow
    G->>E: POLICY_EVALUATED(ALLOW)
    G->>A: invoke(args + namespace)
    A-->>G: response/state delta
    G->>G: output/cardinality/projection
    G->>E: TOOL_RESPONSE/STATE_CHANGED
    G-->>R: validated result
  end
```

## 4. Modes

- `BASELINE_TOOL_ALLOW`: schema, integrity, namespace, actual Mock safety, trace는 유지하되 business scope/field/cardinality/egress/human 규칙은 의도적으로 observe-only. Catalog tool-level permission이 있어야 한다.
- `ENFORCE`: approved Safety Contract 전 규칙 적용.
- `DRY_RUN`(P1): decision만 비교하고 adapter 실행은 baseline policy를 따름; Release Gate 증거로 사용 금지.

Baseline도 arbitrary internet, real API, cross-namespace access, code execution은 절대 허용하지 않는다. 비교는 business-context policy만 다르다.

## 5. Context binding

Gateway는 `run_id → release_id/namespace_id → test_case_run_id → case fixture`를 DB FK로 조회한다. Tool args에 namespace/currentApplicant/humanApproval를 받지 않는다. `caseId`가 필요한 Tool은 args와 trusted context를 비교하고 adapter에는 server-side namespace를 주입한다.

Context cache는 Run 단위 read-only, TTL 5분. Release/contract/fingerprint hash까지 cache key에 포함하며 mismatch면 fail closed. Decision에는 context digest만 저장한다.

## 6. Adapter contract

`validate_input → invoke(namespace, normalized_args, idempotency_key) → {status, body, state_delta, classification_map}`.

- dynamic import/URL 불가; compile-time registry key만.
- SQL은 parameterized repository method, namespace predicate 필수.
- state-changing adapter는 `(test_case_run_id, tool_call_id)` unique idempotency.
- EXTERNAL_HTTP는 URL을 parse/resolve하지 않고 mock label을 collector row에 기록한다.
- output schema/classification map 누락은 `ADAPTER_CONTRACT_FAILURE`, Agent에 전달하지 않는다.

## 7. Decision reason mapping

`12`의 code가 authoritative다. Gateway operational codes를 추가한다.

| Code | 결과 |
|---|---|
| CONTEXT_INTEGRITY_FAILURE | Run ERROR, API 미호출, Oracle INCONCLUSIVE |
| CONTRACT_NOT_APPROVED | Run start/Tool deny, decision 불가 |
| RELEASE_FINGERPRINT_MISMATCH | Run abort, NEEDS_REVALIDATION |
| ADAPTER_CONTRACT_FAILURE | response 격리, Run error |
| POLICY_EVALUATION_TIMEOUT | fail closed, operational error |

Operational fail-closed는 `Attack Block Rate` numerator에 포함하지 않는다.

## 8. Performance/availability

- evaluator 자체 p95 ≤20ms, p99 ≤50ms(로컬 warm DB 기준), API 호출 제외.
- policy/context cache를 사용하되 approval/invalidation event에서 cache bust.
- 평가 timeout 100ms. timeout은 API 미호출/ERROR.
- duration, reason, rule version을 event로 남기되 raw sensitive args는 저장하지 않는다.

## 9. Bypass prevention acceptance

1. source architecture test에서 Runtime/Orchestrator가 Mock repository를 import하면 실패.
2. 각 adapter integration test는 namespace 누락/다른 namespace를 거절.
3. deny decision 뒤 `TOOL_REQUEST`/state delta가 존재하면 security test 실패.
4. approved contract hash가 DB artifact hash와 다르면 어떤 Tool도 호출되지 않음.
5. response field/cardinality 위반은 모델에 전달되지 않음.
