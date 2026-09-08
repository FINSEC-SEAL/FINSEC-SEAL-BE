# C Gateway 실행 연결

C는 실제 A 저장 소스에 연결된 정책 판정을 commit한 뒤 기존 B 어댑터를 호출한다. 응답 검증 실패는 모델 전달을 중단하며, 상태 변경은 기존 B 트랜잭션 안에서 검사해 실패 시 rollback한다. 이 문서의 기능은 로컬 Java 실행 경계이며, 실제 인증·관측 공급자와 전체 정상 Tool 연결은 아래 조건을 충족해야 한다.

## 진입점과 Spring 구성

| 항목 | 파일·계약 |
|---|---|
| 구현 | `policy/LoanReviewPolicyGateway.java`, 기존 B `PolicyGateway` 구현 |
| 호출 | `GatewayResult invoke(SandboxExecutionContext context, ToolInvocation invocation, String actorId)` |
| 구성 | `policy/LoanReviewPolicyGatewayConfiguration.java` |
| 활성화 조건 | `finsec.policy.gateway.enabled=true`; 기본값은 비활성화 |
| 인증 공급자 | `loanReviewGatewayReviewerContext` qualifier의 `Supplier<SafetyContractLifecyclePolicy.ReviewerContext>` bean |
| 실행 관측 공급자 | `GatewayRuntimeObservations` bean |

Java 파일 경로의 기준은 `src/main/java/com/finsecseal/`이다. 기존 A 소스·이벤트 서비스와 B `StateChangingToolExecutionService`, 등록된 `List<ToolAdapter>`는 구성에서 주입한다. 공급자 구현이나 가짜 기본값은 C 구성에 포함하지 않는다.

C를 명시적으로 켜면 `@Primary` Gateway가 실제 B `ToolDispatcher`에 주입된다. 필수 공급자 누락 또는 잘못된 reviewer qualifier는 시작 실패다. `policy.gateway.enabled=true` 또는 `policy.gateway.c.enabled=true`와 동시에 사용할 수 없다. 두 B HTTP client는 별도로 어댑터를 실행하므로 이 로컬 Gateway와 중첩시키면 안 된다. 기존 BASELINE bridge의 등록 조건과 기본 설정은 유지한다. 중복 Tool 이름을 가진 adapter 등록도 거절한다.

Reviewer supplier는 bean 생성 때 고정한 사용자 대신 **매 호출의 실제 인증된 실행 주체**를 반환해야 한다. `actorId`와 일치하고 해당 workspace 권한이 있어야 한다. actor 문자열이나 과거 승인자의 정보를 인증으로 바꾸면 안 된다. A의 HTTP 인증 정보를 B의 비동기 실행에 전달하는 연결은 별도로 필요하다. 호출 주위에 열린 transaction 또는 transaction synchronization이 있으면 `UNSAFE_TRANSACTION`으로 거절한다.

## 입력과 결과

`SandboxExecutionContext`는 기존 B 타입이며 `runId`, `caseRunId`, `traceId`, `mode`, `caseKey`, `currentApplicantId`를 담는다. namespace는 서버의 Run에 연결한다. C는 실제 A Run/Case, Release/Contract, 독립 관측 namespace/context와 다시 대조한다.

`ToolInvocation`에는 `ToolProposal(toolName, arguments)`와 다음 **A가 저장한 실제 event identity**가 필요하다.

- `toolCallId`: 해당 `TOOL_PROPOSED` event의 `eventId`.
- `requestDigest`: 그 event 전체 payload envelope의 `payloadDigest`. arguments만 hash한 값과 다르다.

C는 event의 Run/Case/trace/Tool/ID/digest와 실제 proposal payload를 검증한다. `ToolProposal`만 받는 legacy overload는 `INVALID_INVOCATION` 예외로 거절한다. B 호출자는 기존 canonical `ToolInvocation` 경로를 사용해야 한다.

반환 타입은 기존 `PolicyGateway.GatewayResult`다.

| 결과 | 전달 방식 |
|---|---|
| 정책 DENY | `policyDecision.allowed=false`, 저장된 `policyEvent`; request/response/execution은 null. 어댑터 호출 없음 |
| 검증된 ALLOW | `policyDecision.allowed=true`, 저장된 policy/request/response event와 `ToolExecutionResult` |
| 운영 실패·응답 격리 | 안전한 `LoanReviewPolicyGateway.GatewayException`; 정상 결과나 가짜 DENY를 반환하지 않음 |

`GatewayException.code()`는 `FailureCode`, `reason()`은 선택적 정책 평가 reason, `postCallCheck()`는 선택적 응답 검사 위치를 반환한다. 예외에는 원문 cause/suppressed가 없고 `successfulSecurityBlock()`은 항상 false다. B는 이 정보를 운영 오류로 전달해야 하며 보안 차단 성공으로 집계하면 안 된다.

사용하는 코드는 `INVALID_INVOCATION`, `UNSAFE_TRANSACTION`, `AUTHENTICATION_REQUIRED`, `SOURCE_BINDING_INVALID`, `INVALID_OBSERVATION`, `POLICY_EVALUATION_FAILED`, `POLICY_EVALUATION_TIMEOUT`, `EVIDENCE_FAILURE`, `ADAPTER_UNAVAILABLE`, `ADAPTER_CONTRACT_FAILURE`, `RESPONSE_CARDINALITY_VIOLATION`, `REPLAY_RESPONSE_UNAVAILABLE`이다. 실제 반환 건수 위반은 `RETURNED_CARDINALITY`, 상태 범위 위반은 `STATE_DELTA_PROVENANCE`를 함께 전달한다. ENFORCE 고객 분류 위반은 `CLASSIFICATION`으로 식별된다. 이 accessor가 B/D 저장소에 자동 기록되는 것은 아니므로 소비자 연결이 필요하다.

## 관측 공급자 계약

정확한 Java 타입은 [GatewayRuntimeObservations.java](../src/main/java/com/finsecseal/policy/GatewayRuntimeObservations.java)에 있다. 모든 응답은 동일 `InvocationKey(runId, caseRunId, traceId, toolCallId, requestDigest)`에 결합해야 한다.

| 메서드 | 반환과 실제 출처 요구 |
|---|---|
| `PreCall resolve(InvocationKey, Duration)` | 실제 서버 context, namespace row의 ID/fixture version/digest/정확한 `ACTIVE` 상태, run/case purpose, workflow, 허용 문서·소유관계·문서 출처, 요청 operation |
| `RegistryObservation registry(InvocationKey, Duration)` | 실제 로드된 Release fingerprint와 전체 실제 runtime registry의 Tool/version/trust/schema·description digest. 고정 순서의 Tool Trust 단계에서만 호출 |
| `StateCapture begin(InvocationKey, Duration)` | 해당 실행 전 완전한 state capture의 ID/namespace/digest/coverage |
| `Completion complete(InvocationKey, StateCapture, Duration)` | 동일 call/capture/namespace, 실제 반환 body digest, 실제 classification map, 실행 후 digest와 완전한 변경 목록 |

`StateChange`는 `StateEntity`, namespace, entity ID digest, 선택적 case, before/after version·digest를 담는다. 관측 범위는 LoanCase/Customer/Document/LoanPolicy/ReviewNote/LoanDecision/ExfilEvent이며, 기대 namespace 밖의 변경도 누락시키면 안 된다. `complete=false`나 관측 실패를 빈 변경 목록으로 바꾸지 않는다. row digest/version만으로 CREATE/DELETE, 정확한 생성 건수, version +1, 응답 body와 저장 row의 동일성을 추정하지 않는다.

기대 Run의 fixture 값, 승인 정책의 분류·registry 값 또는 C가 계산한 body digest를 그대로 돌려주면 독립 관측이 아니다. 콜백은 열린 connection/lock/stream을 반환하지 않는다. 컬렉션과 JSON은 복사되며, 호출자에게 반환되는 JSON도 별도 복사본이다.

각 callback에는 양수이고 최대 5초인 남은 `Duration`이 전달된다. registry는 100ms 정책 평가의 남은 시간 안에 완료해야 한다. **공급자가 실제 JDBC/transport timeout을 설정해야 한다.** 인자 전달이나 elapsed-time 확인만으로 임의의 동기 I/O를 강제 중단할 수는 없다. C는 transaction context를 잃는 별도 실행 thread pool을 추가하지 않는다.

## 트랜잭션과 응답 격리

소스 인증·Run/Case·현재 정책/Release/namespace 결합, 고정 순서 평가와 `POLICY_EVALUATED` 저장은 C 소유의 writable REPEATABLE READ transaction에서 수행한다. transaction timeout은 5초이며, commit과 Release lock 해제 후 어댑터를 호출한다. 실제 Run은 `RUNNING`, Case는 `EXECUTING`이어야 한다.

ENFORCE는 현재 승인 계약을 사용한다. BASELINE은 실제 Release 선언과 catalog를 사용하고 승인 조회를 가장하지 않는다. BASELINE의 business object/field/cardinality/egress/human 검사는 observe-only로 표시하되 schema, integrity, namespace, catalog 실행 권한, workflow, trust는 유지한다. `stageOutcomes`는 관측 위반과 실제 DENY/ERROR, 미평가 단계를 구분한다. 고객 응답의 business 위반 관측도 `observedPostCall`로 구분한다. P1 DRY_RUN 실행 모드는 이번 연결에 포함하지 않는다.

읽기 호출은 request를 commit한 뒤 어댑터를 실행한다. 동일한 고정 응답에 schema·body digest·분류·scope/projection/cardinality·상태 검증을 수행한 뒤 첫 `TOOL_RESPONSE`를 `deliveryState=PENDING`, `deliveredToAgent=false`로 저장한다. 이후 모델 전달은 B의 실제 Runtime/Dispatcher/Loop 책임이다.

상태 변경은 기존 B `StateChangingToolExecutionService.execute` Spring proxy에 C의 private validating delegate를 전달한다. C 검사는 B가 첫 response와 완료 receipt를 쓰기 전에 실행된다. 실패하면 B transaction의 변경/request/receipt가 rollback되고, 먼저 commit한 정책 판정은 남는다. 별도 C executor/idempotency 저장소나 중복 response event는 만들지 않는다. 기존 receipt replay는 redacted 응답을 반환하므로 `REPLAY_RESPONSE_UNAVAILABLE`로 격리하며 재실행하거나 response를 중복 저장하지 않는다.

고객 읽기와 정상 READ/SEARCH는 실제 `stateChanged=false`, 빈 변경 목록, 동일 before/after digest를 요구한다. ReviewNote는 변경된 모든 자원의 namespace/entity/요청 case 범위를 확인한다. ENFORCE의 current case 제한과 BASELINE의 current-case observe-only를 구분한다. 범위가 맞아도 **비고객 필드/path 분류 계약이 미정이므로 현재 비고객 응답은 계속 격리한다.** 이 상태 비교는 정상 ReviewNote 생성이나 전체 정상 workflow 성공 증명이 아니다.

## 선행 작업과 남은 C 작업

| 담당 | 현재 상태와 필요한 연결 | 영향을 받는 C 작업 |
|---|---|---|
| A/B | 실제 실행 주체의 reviewer 공급자, 호출별 namespace/context/registry/완전한 상태·분류 관측 공급자와 유효한 I/O timeout 구현 필요 | 실제 환경에서 C 모드 활성화 및 응답 전달 보장 |
| B | 실제 고객 분류 JSON은 `sensitiveFields`, `criticalFields`, `syntheticOnly`이며 C가 요구하는 field-to-taxonomy map이 아님. golden fixture를 임의 변경하지 않고 실제 adapter 응답 계약을 제공해야 함 | 실제 고객 post-call 분류 검증. 현재 원본 분류는 운영 오류로 격리 |
| B | 실제 fixture의 상태는 `IN_REVIEW`, context에는 C가 요구하는 workflow/purpose projection이 없음. 이를 `DOCUMENT_REVIEW`로 임의 변환하지 않음 | 실제 business context/workflow 결합 |
| B | 기존 Customer adapter와 state-changing executor는 호출 가능. 정상 `CASE_CONTEXT_READ`, `DOCUMENT_READER`, `LOAN_POLICY_SEARCH`, `REVIEW_NOTE_WRITE` adapter 연결은 미제공 | 전체 정상 대출 workflow의 실제 실행 |
| A/B/C 계약 | A catalog에 비고객 Tool 단위 `dataClassifications`는 있으나 필드/path별 map·배열 coverage 계약은 미정. Tool 단위 NORMAL을 모든 필드 분류로 확장하지 않음 | 비고객 응답의 전체 분류 검증과 격리 해제 |
| A/B | BASELINE에도 실제 Release의 catalog 실행 권한 필요. server catalog에 high-impact Tool이 존재한다는 사실만으로 실행 권한이 생기지 않음 | FA-01/02/03 전체 BASELINE 대 ENFORCE 실행 비교; 조건부 테스트를 실제 FA acceptance로 계산할 수 없음 |
| B/D | B `RunExecutionLifecycleService.sealFailure`는 Run을 `FAILED`로 저장하지만 D `ReleaseAssuranceService` 집계는 `COMPLETED` Run만 조회 | 저장된 운영 오류까지 포함하는 실제 지표 연결. C의 ERROR/격리를 ABR 성공으로 바꾸면 안 됨 |
| C | 현재 매 호출 실제 source/context를 읽음. 정책 의미 검증 결과 memoization은 다음 C 구현 단위. 전체 source/PreCall/실행 권한을 재사용하지 않음 | C 정책 cache 잔여 구현 |
| A/B/C | A의 승인·무효화 저장/감사 조회는 이미 존재. 커밋된 통지의 구독·재전달과 immutable context/호출별 관측 분리 계약은 미제공 | 실제 context 조회 cache와 승인·무효화 시 cache bust 운영 연결 |
| C 및 owner read | 역사적 Replay 비교 입력 조립은 별도 C 잔여 작업. 실제 기록된 controls/승인 시각을 읽는 연결 필요 | fully stored controlled-replay 검증 |

A 비동기 생성 연동은 개발 중 원격 확인 시 [PR #45](https://github.com/FINSEC-SEAL/FINSEC-SEAL-BE/pull/45), head `f6ee5691a1f11096b96cb3fc9bfc4a1e1de01686`, OPEN/DRAFT였다. 이는 2026-09-08 확인 스냅샷이며 이후 merge 여부는 다시 확인해야 한다. 해당 구현을 존재하지 않는 API로 취급하지 않는다. C 생성 진입점 `ContractCandidateGenerationService.generate(VersionIdentity,String,String)`와 `SafetyContractPatchGenerationService.generate(UUID,UUID,ReviewerContext)`는 별도 구현돼 있다.

기존 FE 작업은 별도 하네스의 SUP102 기록으로 보류돼 있다. 이 BE 기능이 그 FE build/typecheck 실패나 A 비동기 API UI 연결을 해결한 것은 아니다.

## 검증 범위

| 요구·검증 | 테스트와 해석 |
|---|---|
| C-GW-001/004/005, 고정 순서·소스 결합 | `LoanReviewPolicyGatewayTest`, `GatewayApprovedPolicySourceService*`, `GatewayBaselinePolicySourceService*`: 실제 A 저장 source integration과 C 결정 순서/권한/해시/관측 결합 |
| C-GW-006/007/008, 실제 실행 경계 | `LoanReviewPolicyGatewayIntegrationTest`: 실제 PostgreSQL/A 서비스/B Spring proxy/Customer adapter/B caller. 실제 분류 격리, 정책 commit·lock 해제, append rollback, receipt replay, foreign namespace 변경 rollback, 유효한 DB 중단 |
| 조건부 정상 전달 | 동일 PG suite의 명시적 `SyntheticClassificationFixture`와 합성 인증/workflow/purpose/registry 연결을 사용. 원본 B 분류·golden digest를 바꾸지 않음. 실제 production provider 증명은 아님 |
| 상태 범위·무응답 | `LoanReviewPolicyGatewayTest`와 PG의 private 악성 ReviewNote probe. scope 수용 후에도 비고객 classification 격리 유지. 기록용 unit transaction은 실제 B rollback 증거와 구분 |
| TC-GW-012, source 경계 | `GatewayExecutionAcceptanceTest`: 실제 Runtime/Orchestrator 발견이 비면 실패, import/FQN 및 범위를 한정한 AST receiver 검사와 음성 fixture. Java 전체 타입 추론/reflection 우회 분석은 아님 |
| TC-GW-014, 성능 | 실제 schema preflight+evaluator, warm-up 2,000회/측정 5,000회, 실제 nanoTime과 p95/p99. facts 조립·DB/source/전체 Gateway/adapter/API/model 비용 제외 |
| TC-OR-007/TC-MET-002, D consumer | 실제 Oracle의 누락 증거 INCONCLUSIVE 및 calculator의 운영 오류 분리. `FAILED` Run을 포함하는 실제 저장 집계 증명은 아님 |
| Spring 구성 | `LoanReviewPolicyGatewayConfigurationTest`: 명시적 선택, 필수 공급자/qualifier/중복 adapter/remote 충돌 실패, 실제 Dispatcher와 무fallback. 합성 공급자로 실제 인증 완료를 주장하지 않음 |

하네스 Run은 `20260908T073232Z-c0d95de2`다. 실패 기록과 복구 검증을 보존하며, 기능 전달 전에 정확한 최종 파일의 fresh focused/full 테스트, native Supervisor checkpoint와 정상 post gate를 수행한다. 조건부 실행 경계의 구현을 전체 C·Gateway·FA·Replay·운영 검증 완료로 확대하지 않는다.
