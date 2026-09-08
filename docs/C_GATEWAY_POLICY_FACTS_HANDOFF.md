# C 승인 정책의 검증 입력 연결

`GatewayPolicyFactsAssembler`는 승인 계약 출처와 요청을 기존 Field Scope,
Cardinality, Human Boundary 검증기의 입력으로 변환한다. Spring 컴포넌트이며
`ToolProposalValidator`를 주입받는다. 저장·Tool 실행·정책 판단 기록을 하지 않는다.

## 진입점과 반환 계약

파일: `src/main/java/com/finsecseal/policy/GatewayPolicyFactsAssembler.java`

| 메서드 | 입력 | 성공 반환 |
|---|---|---|
| `customerDataRead(source, proposal)` | `ApprovedPolicySource`, B의 `ToolProposal` | `CustomerDataReadFacts`: `fieldScope()`와 `cardinality()` |
| `humanBoundary(source, requestedTool)` | 같은 출처, 원문 Tool 이름 `String` | 기존 `PolicyHumanBoundaryFacts` |

`source`는 `GatewayApprovedPolicySourceService.load(runId, testCaseRunId, reviewer)`에서
얻는다. A가 검증할 실제 `ReviewerContext`를 전달해야 한다. actor 문자열로 인증 문맥을
만들면 안 된다. 출처 조회의 트랜잭션·실패 계약은
[승인 출처 인계 문서](C_GATEWAY_APPROVED_POLICY_SOURCE_HANDOFF.md)를 따른다.

```java
var source = approvedSources.load(runId, testCaseRunId, reviewer);
var customer = facts.customerDataRead(source, invocation.proposal());
// 기존 Gateway의 각 단계에서 사용한다. 아래 입력 생성 자체는 단계 PASS가 아니다.
var fieldFacts = customer.fieldScope();
var cardinalityFacts = customer.cardinality();
var humanFacts = facts.humanBoundary(source, invocation.proposal().toolName());
```

고객 조회 메서드는 `CUSTOMER_DATA_READ`만 지원한다. B의 실제 인자 검증기를 JSON
복사본에 적용하고 C에서 중복 고객 ID·필드를 거절한다. 허용 필드로 미리 걸러내거나
trim·대소문자 변환·중복 제거하지 않는다. 서로 다른 고객 두 명이면 요청 건수는 2다.
이 값은 현재 신청인과의 동일성을 증명하지 않는다. 반환값에는 고객 ID나 전체 요청
JSON을 보관하지 않으며, 요청 필드 이름·순서는 검증에 필요하므로 그대로 보존한다.

승인 계약의 필드 정책·건수 제한·필수 high-impact 매핑이 없거나 타입·참조가 잘못되면
기본 허용값을 만들지 않는다. 정수 절삭이나 문자열·실수의 정수 변환도 하지 않는다.
Human Boundary의 catalog는 enabled Tool과 high-impact Tool의 합집합이다.
`allowedTools` 밖의 `LOAN_DECISION_UPDATE`도 인간 승인 전용으로 유지된다.
미등록 Tool의 사실이 생성되더라도 기존 Human Boundary 검증기는 Tool 단계가 먼저
해결되지 않은 입력을 예외로 거절하며 PASS를 반환하지 않는다.

## 실패 전달

두 메서드는 동기 호출이다. 실패하면 `FactAssemblyException`을 던지며 `code()`로
아래 값을 전달한다. 부분 결과·overall ALLOW·정책 DENY 응답을 반환하지 않는다.

| 코드 | 원인 |
|---|---|
| `INVALID_REQUEST` | 요청·Tool 이름·인자 형식/크기 오류, 중복 고객 ID/필드, B 검증 실패 |
| `UNSUPPORTED_TOOL` | 고객 조회 메서드에 정상 형식의 다른 Tool 이름을 전달함 |
| `INVALID_POLICY_SOURCE` | 출처 없음, 필수 정책·catalog 누락, 정책 타입·정수 범위·참조 오류 |

메시지는 `Gateway policy facts unavailable: <CODE>`로 고정한다. 원시 요청·정책·의존성
예외를 메시지, cause, suppressed exception으로 전달하거나 기록하지 않는다.
호출자는 기존 Gateway의 실패 처리 흐름에 연결해야 하며 실패를 ALLOW로 바꾸면 안 된다.

## 검증 범위와 후속 연결

TC-GW-003/004/006의 **구성 요소 검증**: 실제 승인 출처 서비스와 B 인자 검증기,
기존 세 평가기를 조합해 중복 INVALID_REQUEST, FIELD_SCOPE_VIOLATION,
RECORD_LIMIT_EXCEEDED, HUMAN_ONLY_ACTION 및 정상 단계 PASS를 확인한다.
출처 서비스의 단위 fixture는 A 조회를 mock한 조합 테스트이며 DB 승인·잠금 증거는
기존 승인 출처 PostgreSQL 통합 테스트에 있다.

이 조립은 출처와 invocation의 저장 이벤트 결합, preflight, 전체 단계 순서 또는
실행 권한을 증명하지 않는다. `ToolInvocation.requestDigest`는 B의 저장 이벤트
payload digest 계약을 유지해야 하며 인자 JSON hash로 새로 만들지 않는다.

| 담당 | 필요한 후속 입력·연결 | 해당 입력이 없으면 남는 C 연결 |
|---|---|---|
| A/B | 인증된 reviewer와 Run/CaseRun에 결합된 서버 namespace·case·applicant·workflow·문서 소유 관계 | 출처 조회의 실제 진입점, Business Context/Object Scope/Workflow 사실 조합 |
| B | 실제 요청 operation과 관찰된 registry/schema/description digest 및 trust 출처 | Tool/Operation/Egress/Trust 검증 입력 조합 |
| B | 응답 필드 타입·분류 출처, state provenance, Agent 전달/격리 hook | 실제 응답 검증 및 격리 연결 |
| D | 실제 실행 증거를 이용한 공격 성공·실패와 오류/비교불가 처리 | 공격 결과·Replay 지표 검증 |

A의 승인 저장 조회와 Release 선언 catalog API는 이미 존재한다. 선언값을 expected와
observed 양쪽에 넣어 무결성 검사를 통과시키거나 B의 DTO만으로 서버 출처를 보장하면
안 된다. 현재 B `ToolExecutionResult(output, stateChanged)`만으로는 응답 분류·상태
출처를 채울 수 없다.

TC-GW-010/011/012/013 및 TC-OR-007/TC-MET-002의 실제 실행·전달·판정 연결,
FA-01/02/03의 no-call/no-leak/no-state-delta와 controlled Replay는 이 조립기의 완료
범위가 아니다. 무SQL·무실행 단위 테스트를 실제 공격 차단 증거로 보고하지 않는다.
