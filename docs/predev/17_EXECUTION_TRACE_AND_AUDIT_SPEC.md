# Execution Trace and Audit Specification

## 1. 목적

Trace는 raw chain-of-thought가 아니라 관찰 가능한 model interaction 요약, Tool proposal, policy decision, API response, state delta, Oracle evidence를 순서대로 연결한다. UI/Report는 이 event stream을 source of truth로 사용한다.

## 2. Event types

| Event | producer | 필수 metadata |
|---|---|---|
| RUN_STARTED | Orchestrator | mode, release fingerprint, suite/fixture/contract hash |
| MODEL_REQUEST | Runtime | provider/model, prompt digest, tool schema set hash, token estimate |
| MODEL_RESPONSE | Runtime | response digest, resolved model, finish reason, toolCallIds |
| TOOL_PROPOSED | Runtime | toolName, normalized input redacted/digest |
| POLICY_EVALUATED | Gateway | allowed, reason, failedCheck, policy/context/input hash, duration |
| TOOL_REQUEST | Gateway | adapter, namespace, request digest |
| TOOL_RESPONSE | Gateway | status, output redacted/digest, classification map |
| SANDBOX_STATE_CHANGED | Adapter | entity type/id hash, before/after version/digest |
| ORACLE_EVALUATED | Oracle | outcome, reason, invariant, evidence digest |
| FINDING_CREATED | Finding Service | finding id/category/severity/oracle id |
| RUN_COMPLETED | Orchestrator | status, counts, metric snapshot hash |

추가 운영 event: `RUN_CANCEL_REQUESTED`, `RUN_FAILED`, `BUDGET_UPDATED`, `CONTRACT_APPROVED`, `RELEASE_INVALIDATED`, `ATTESTATION_GENERATED`, `DEMO_RESET`.

## 3. Event schema

```json
{
  "schemaVersion": "1.0",
  "eventId": "uuidv7",
  "traceId": "uuid",
  "runId": "uuid",
  "testCaseRunId": "uuid-or-null",
  "sequence": 42,
  "occurredAt": "2026-08-09T12:00:00.123Z",
  "eventType": "POLICY_EVALUATED",
  "toolName": "CUSTOMER_DATA_READ",
  "input": {"customerIds": ["[SYNTH_ID:c1]"], "fields": ["incomeBand"]},
  "output": null,
  "payloadDigest": "sha256:...",
  "policyDecision": {"allowed": false, "reasonCode": "CUSTOMER_SCOPE_VIOLATION"},
  "reasonCode": "CUSTOMER_SCOPE_VIOLATION",
  "metadata": {"policyVersionId": "uuid", "durationMs": 1.2},
  "prevEventHash": "sha256:...",
  "eventHash": "sha256:..."
}
```

`sequence`는 TestRun 전체에서 1부터 증가하며 `(run_id,sequence)` unique다. DB advisory lock/`run_event_counter FOR UPDATE`로 할당한다. `occurredAt`은 표현용이고 정렬 source는 sequence다. batch insert 실패 시 sequence gap은 허용하되 `EVENT_GAP` audit alert를 만들고 decision을 REVIEW로 제한한다.

## 4. Correlation

- `traceId`: 한 TestCaseRun의 model/tool loop 전체.
- `modelRequestId`, `toolCallId`, `policyDecisionId`, `adapterRequestId`, `oracleResultId`를 metadata로 연결.
- Replay는 새 trace/run이지만 `replay_link`로 baseline case run과 attack variant hash를 연결.
- SSE event id는 canonical `sequence`; UI가 중복 dedupe.

## 5. Redaction/classification

| 분류 | Event/UI 처리 | Evidence vault |
|---|---|---|
| NORMAL synthetic | 필요 최소 표시 | raw 허용 |
| PII | deterministic token `[SYNTH_ID:c1]` | encrypted raw + 접근 audit |
| SENSITIVE_PII | field name만, 값 `[REDACTED:SENSITIVE_PII]` | 원칙상 raw report 금지; test token hash |
| FINANCIAL/CREDIT | band는 표시 가능, account는 redacted | encrypted raw/token hash |
| SECRET | 절대 저장 금지, detection 시 Run abort | 없음 |

Redaction은 field classification registry와 pattern detector를 함께 쓴다. request/output raw payload는 digest를 먼저 계산하고 redacted JSON을 event에 저장한다. 합성임을 표시하더라도 secret-like 값은 log하지 않는다.

## 6. MODEL event policy

- System prompt 원문은 ReleaseArtifact에서 권한 기반 조회; Event에는 hash/length만.
- Document excerpt는 기본 저장하지 않고 document id/content hash/trust label만.
- Provider response는 tool call과 final structured result만 정규화; hidden reasoning/chain-of-thought를 요청·보존·표시하지 않는다.
- Debug raw capture는 production/demo 기본 OFF, local explicit flag에서도 합성 데이터/24h TTL/접근 audit.

## 7. Audit immutability

- application DB role은 INSERT/SELECT만, UPDATE/DELETE 불가.
- 각 eventHash=`SHA256(canonical(event without hashes) || prevEventHash)`; Run complete 시 head hash를 decision input에 봉인.
- 일 단위 event partition retention은 최소 대회 종료+90일, 설정 변경은 governance audit.
- hash chain은 외부 공증이 아니므로 DB superuser 공격을 완전히 방어한다고 주장하지 않는다. P2에서 WORM/object lock 가능.

## 8. SSE/redelivery

Canonical event commit 후 outbox row를 같은 transaction에 기록한다. publisher가 SSE로 projection하며 at-least-once delivery다. UI는 `(runId,sequence)`로 dedupe한다. heartbeat에는 증거 데이터가 없다. reconnect가 retention을 벗어나면 REST snapshot과 최근 cursor를 다시 받는다.

## 9. Trace UI projection

기본 행: sequence/time, actor lane(Agent/Gateway/API/Oracle), action, decision badge, reason, duration. 클릭 시 redacted input/output, policy check list, state diff, evidence link를 보인다. `MODEL_RESPONSE`의 자연어는 접힌 상태이며 Tool/API/Event가 우선이다.

## 10. Acceptance

1. 대표 attack trace에 RUN_STARTED→MODEL→TOOL_PROPOSED→POLICY→(API/STATE)→ORACLE→FINDING→RUN_COMPLETED가 순서대로 존재.
2. deny replay에는 TOOL_REQUEST/STATE_CHANGED가 없음.
3. event hash tamper/gap test가 탐지됨.
4. secret canary가 log/SSE/report에 0회 등장.
5. SSE disconnect/reconnect에서 event 누락 0, 중복은 UI에서 0개로 보임.
