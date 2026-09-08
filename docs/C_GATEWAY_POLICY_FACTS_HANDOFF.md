# C 승인 정책의 검증 입력 연결

`GatewayPolicyFactsAssembler`는 승인 계약 출처와 요청을 기존 Field Scope,
Cardinality, Human Boundary, Tool/Operation, Egress, Workflow, Business Context,
Object Scope 및 고객 응답 검증기의 입력으로 변환한다. Spring 컴포넌트이며
`ToolProposalValidator`를 주입받는다. 저장·Tool 실행·정책 판단 기록을 하지 않는다.

## 진입점과 반환 계약

파일: `src/main/java/com/finsecseal/policy/GatewayPolicyFactsAssembler.java`

| 메서드 | 입력 | 성공 반환 |
|---|---|---|
| `customerDataRead(source, proposal)` | `ApprovedPolicySource`, B의 `ToolProposal` | `CustomerDataReadFacts`: `fieldScope()`와 `cardinality()` |
| `humanBoundary(source, requestedTool)` | 같은 출처, 원문 Tool 이름 `String` | 기존 `PolicyHumanBoundaryFacts` |
| `toolAuthorization(source, requestedTool, requestedOperation)` | 같은 출처, 요청 Tool 이름과 독립된 원문 operation | 기존 `PolicyToolAuthorizationFacts` |
| `egress(source, requestedTool)` | 같은 출처, 요청 Tool 이름 | 기존 `PolicyEgressFacts` |
| `workflow(source, requestedTool, serverWorkflowStage)` | 같은 출처, 요청 Tool, 독립 서버 단계 원문 | 기존 `PolicyWorkflowFacts` |
| `businessContext(source, serverResolved, releasePurpose, runPurpose, casePurpose, namespaceId, caseId, currentApplicantId, workflowStage, allowedDocumentIds)` | 같은 출처, boolean과 기존 `Optional<String>`/`Optional<List<String>>` 서버 값 | 기존 `PolicyBusinessContextFacts` |
| `objectScope(source, requestedTool, requestedCaseId, requestedDocumentIds, requestedCustomerIds, currentCaseId, currentApplicantId, allowedDocumentIds, documentOwnerships)` | 요청과 서버 값을 별도 Optional로 전달, ownership은 기존 `DocumentOwnership` 목록 | 기존 `PolicyObjectScopeFacts` |
| `customerDataReadPostCall(source, executedProposal, currentApplicantId, adapterResponse, adapterClassificationMap, adapterStateDeltaProvenance)` | 같은 출처, 실제 실행 요청, 독립 서버 신청자, raw `JsonNode` 관찰값 3개 | 기존 `EnforcePolicyPostCallFacts` |

문맥·고객 응답 연결에는 **customer catalog 메타데이터 투영과 위 assembler 메서드가
모두 필요**하다. adapter만 변경한 중간 단계는 해당 연결의 완성이 아니다.

Tool/Operation·Egress 연결에는 **adapter의 `declaredTools` 투영과 assembler의 두 진입점이
함께 필요**하다. adapter만 갱신한 중간 단계에서는 새 진입점을 사용할 수 없다.
`source.catalog().declaredTools()`는 검증된 동일 릴리스 snapshot의 normal Tool과 서버
high-impact Tool을 이름순으로 보관한다. 실제 v1.1의 5개 normal Tool에 인간 전용
`LOAN_DECISION_UPDATE`를 더한 6개이며, Tool Trust의 활성 binding은 기존 5개다.
기존 6·7개 인자 catalog 생성자는 호환용으로 빈 선언 목록을 가지므로 두 신규 조립
메서드에 사용할 수 없다. 조립 시 선언 이름은 semantic catalog 전체와 정확히 일치해야 한다.

operation은 A의 `READ/SEARCH/CREATE/WRITE/UPDATE/POST` 선언을 그대로 투영한다.
`sideEffectType`의 `NONE/INTERNAL_WRITE/HIGH_IMPACT_WRITE`는 INTERNAL,
`MOCK_EXTERNAL_WRITE`는 EXTERNAL로 분류한다. 누락·잘못된 타입·알 수 없는 값은
catalog 오류이며, trim·대소문자 변환·기본 INTERNAL 처리를 하지 않는다.

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
// requestedOperation은 B가 실제 요청에서 전달할 독립 입력이다. 선언 operation을 복사하지 않는다.
var toolFacts = facts.toolAuthorization(source, invocation.proposal().toolName(), requestedOperation);
var egressFacts = facts.egress(source, invocation.proposal().toolName());
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

Tool/Operation은 요청 operation을 변경 없이 전달한다. 실제 `CUSTOMER_DATA_READ`의
선언 `READ`에 대해 요청 `WRITE`, `read`, `READ `는 기존 평가기에서
`OPERATION_NOT_ALLOWED`가 된다. null·공백 operation은 `INVALID_REQUEST`다.
미등록 Tool은 Tool 단계에서 `TOOL_NOT_ALLOWED`이며, Egress 단계에 곧바로 넣으면
미해결 Tool 예외가 발생한다. 인간 전용 Tool은 기존 Tool 단계의 위임 규칙을 유지하고
Human Boundary 단계에서 `HUMAN_ONLY_ACTION`으로 판단한다.

두 신규 메서드는 승인 정책의 `externalEgress.allowed`와 `allowedDestinations`를 함께
검사한다. P0의 `false`와 빈 배열은 유효하다. true, 비어 있지 않은 목적지,
누락·타입 오류를 허용 정책으로 보정하지 않는다. 목적지 문자열은 그대로 검사한다.
실제 현재 catalog의 6개는 모두 INTERNAL이며, 이 결과를 외부 유출 공격 차단 증거로
해석하면 안 된다. 실제 승인 출처에 없는 외부 Tool을 추가하지 않는다.

## 실패 전달

모든 메서드는 동기 호출이다. 출처 투영·일반 입력 실패는 `FactAssemblyException`의 `code()`로
아래 값을 전달한다. 부분 결과·overall ALLOW·정책 DENY 응답을 반환하지 않는다.

| 코드 | 원인 |
|---|---|
| `INVALID_REQUEST` | 요청·Tool 이름·인자 형식/크기 오류, 중복 고객 ID/필드, B 검증 실패 |
| `UNSUPPORTED_TOOL` | 고객 조회 메서드에 정상 형식의 다른 Tool 이름을 전달함 |
| `INVALID_POLICY_SOURCE` | 출처 없음, 필수 정책·catalog 누락, 정책 타입·정수 범위·참조 오류 |

메시지는 `Gateway policy facts unavailable: <CODE>`로 고정한다. 원시 요청·정책·의존성
예외를 메시지, cause, suppressed exception으로 전달하거나 기록하지 않는다.
호출자는 기존 Gateway의 실패 처리 흐름에 연결해야 하며 실패를 ALLOW로 바꾸면 안 된다.

`objectScope`의 caller 요청·서버 문맥 실패는 기존 Facts의
`InvalidPolicyScopeRequestException`과 `PolicyScopeContextIntegrityException`을 각각
그대로 전달한다. 요청 스키마 오류와 서버 무결성 오류를 구분하기 위한 것이며, 메시지는
필드명만 포함한다. source 접근 중 발생한 오류는 여전히 안전한 `INVALID_POLICY_SOURCE`다.

## 업무 문맥과 객체 범위

Workflow는 실제 승인 `workflow.allowedStages`를 읽고 현재 단계는 서버 입력 그대로
보존한다. catalog 전체 중 정확한 `CASE_CONTEXT_READ`만 bootstrap이다. 미등록 Tool의
선행 Tool 단계가 해결되지 않았으면 기존 평가기는 예외를 반환한다.

Business Context는 계약 purpose만 승인 source에서 가져온다. `serverResolved=false`,
누락·불일치 purpose/ID/단계/문서 목록을 채우거나 수선하지 않는다. null Optional wrapper는
입력 오류이며, Optional 안의 잘못된 서버 값은 기존 평가기의 무결성 판단으로 전달된다.

Object Scope는 `resourcePolicies`의 모든 Tool 규칙을 순회한다. 지원되는
`CURRENT_CASE_ONLY`/`ALLOWED_DOCUMENTS_ONLY`를 읽고 고객 조회의
`CURRENT_APPLICANT_ONLY`와 Tool별로 병합한다. 필수 문서·검토 메모 규칙, 참조하는 enabled
Tool, 알려진 속성·값을 확인하며 빈 규칙이나 미지원 제약을 무시하지 않는다.
요청값·서버 기준값·저장된 문서 소속은 서로 대신 만들지 않는다.

## 고객 응답의 기대값과 관찰값

`source.catalog().customerOutputFields()`는 같은 A snapshot의 고객
`outputSchema.properties.rows.items.properties.fields.properties`에서 필드명과 타입을
읽는다. 기대 분류는 명세 `05_FINANCIAL_DOMAIN_MODEL.md`의 `loan-review/1` 규칙이다.

| 필드 | 기대 분류 | 실제 v1.1 타입 |
|---|---|---|
| accountNumber | FINANCIAL | STRING |
| employmentStatus | NORMAL | STRING |
| incomeBand | FINANCIAL | STRING |

목록은 이름순·불변이며 customerId나 다른 경로의 필드를 추가하지 않는다. 정확한
`string`/`integer`만 기존 STRING/INTEGER로 투영하며 INTEGER 테스트는 합성 catalog다.
세 필드 누락·추가, 잘못된 schema/type에는 기본값을 만들지 않고 catalog 오류를 반환한다.
기존 6·7·8인자 SourceBoundCatalog 생성자는 새 메타데이터가 비어 있어 기존 소비자는
호환되지만 새 post-call 조립에는 사용할 수 없다.

Post-call 조립은 `purpose=LOAN_DOCUMENT_COMPLETENESS_REVIEW`,
`metadata.templateVersion=loan-review/1` 결합,
승인 projection과 `denyUnknown=true`, 양의 정수 `maxReturnedRecords`를 사용한다.
요청 건수 제한이나 반환 rows 수를 반환 한도로 대신하지 않는다. 요청 JSON은 B 인자
검증기에 복사본으로 전달하고, catalog에 있는 금지 필드 accountNumber도 요청에서
삭제하지 않아 실제 guard가 FIELD_PROJECTION 위반을 판단할 수 있다.

기대 namespace는 현재 B의 저장 계약에 따라 `source.runId().toString()`이며 기대
caseRun은 `source.testCaseRunId()`다. 이는 실제 namespace의 존재·ACTIVE 상태나 해당
namespace에서 실행됐다는 증거가 아니다. caller는 실행한 proposal과 독립 서버 신청자,
실제 관찰값을 전달해야 한다. 응답으로부터 기대 분류·신청자·provenance를 만들지 않는다.

```java
var responseFacts = facts.customerDataReadPostCall(source, executedProposal,
        serverApplicantId, response, classificationMap, stateDeltaProvenance);
var responseDecision = guard.evaluate(responseFacts);
// QUARANTINE이면 deliverableOutput()이 비어 있다. 실제 전달 hook은 별도 연결한다.
```

null·잘못된 JSON 응답/분류/provenance를 정상값으로 보정하지 않는다. 기존 guard의
OUTPUT_SCHEMA → CLASSIFICATION → OBJECT_SCOPE → FIELD_PROJECTION →
RETURNED_CARDINALITY → STATE_DELTA_PROVENANCE 순서를 따른다. Java null provenance는
기존 optional 부재 의미를 유지하며 JSON null이나 빈 object는 제공된 잘못된 값으로
격리된다. QUARANTINE은 operational failure이며 `successfulSecurityBlock=false`다.

## 검증 범위와 후속 연결

TC-GW-003/004/006의 **구성 요소 검증**: 실제 승인 출처 서비스와 B 인자 검증기,
기존 세 평가기를 조합해 중복 INVALID_REQUEST, FIELD_SCOPE_VIOLATION,
RECORD_LIMIT_EXCEEDED, HUMAN_ONLY_ACTION 및 정상 단계 PASS를 확인한다.
출처 서비스의 단위 fixture는 A 조회를 mock한 조합 테스트이며 DB 승인·잠금 증거는
기존 승인 출처 PostgreSQL 통합 테스트에 있다.

Tool/Operation·Egress 구성 요소 검증은 실제 A 저장 Tool 메타데이터와 버전된 서버
catalog를 사용한 승인 출처 PostgreSQL 테스트를 포함한다. 정상·불일치 operation,
미등록 Tool, 인간 전용 위임과 INTERNAL Egress를 기존 평가기로 확인한다.
source 조회 이후 조립은 추가 A 조회·감사·도메인 변경을 만들지 않으며, 출처 조회의
기존 감사 2건은 유지한다. 두 신규 메서드는 B 인자 검증기나 Tool 실행기를 호출하지 않는다.

이 조립은 출처와 invocation의 저장 이벤트 결합, preflight, 전체 단계 순서 또는
실행 권한을 증명하지 않는다. `ToolInvocation.requestDigest`는 B의 저장 이벤트
payload digest 계약을 유지해야 하며 인자 JSON hash로 새로 만들지 않는다.

| 담당 | 필요한 후속 입력·연결 | 해당 입력이 없으면 남는 C 연결 |
|---|---|---|
| A/B | 인증된 reviewer와 Run/CaseRun에 결합된 서버 namespace·case·applicant·workflow·문서 소유 관계 | 출처 조회 및 구현된 문맥·객체 범위 조립기의 실제 Runtime 연결 |
| B | 실제 요청 operation과 관찰된 registry/schema/description digest 및 trust 출처 | 구현된 Tool/Operation/Egress 조립기와 expected Trust 기준의 실제 Runtime 연결 |
| B | 응답 필드 타입·분류 출처, state provenance, Agent 전달/격리 hook | 실제 응답 검증 및 격리 연결 |
| B | CASE_CONTEXT_READ/DOCUMENT_READER/LOAN_POLICY_SEARCH/REVIEW_NOTE_WRITE 실제 BE ToolAdapter | 정상 대출 전체 실행과 해당 Tool 응답의 실제 C 검증 연결 |
| D | 실제 실행 증거를 이용한 공격 성공·실패와 오류/비교불가 처리 | 공격 결과·Replay 지표 검증 |

A의 승인 저장 조회와 Release 선언 catalog API는 이미 존재한다. 선언값을 expected와
observed 양쪽에 넣어 무결성 검사를 통과시키거나 B의 DTO만으로 서버 출처를 보장하면
안 된다. 현재 B `ToolExecutionResult(output, stateChanged)`만으로는 응답 분류·상태
출처를 채울 수 없다.

문맥·고객 응답 구성 요소 테스트는 실제 승인 source의 PostgreSQL 조회 후 synthetic 서버
문맥·응답으로 기존 평가기와 guard를 조합한다. source의 감사 2건 이후 추가 owner 호출·
감사·검증 대상 도메인 변경은 0이다. synthetic 입력은 실제 Runtime 실행 증거가 아니다.
세 문맥 메서드는 B 인자 검증기를 호출하지 않으며 post-call은 검증만 호출한다.

TC-GW-010/011/012/013 및 TC-OR-007/TC-MET-002의 실제 실행·전달·판정 연결,
FA-01/02/03의 no-call/no-leak/no-state-delta와 controlled Replay는 이 조립기의 완료
범위가 아니다. 무SQL·무실행 단위 테스트를 실제 공격 차단 증거로 보고하지 않는다.
