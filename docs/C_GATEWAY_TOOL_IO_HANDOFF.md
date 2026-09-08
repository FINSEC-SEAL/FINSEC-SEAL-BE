# C Tool 입력·출력 검증 연결

승인된 릴리스의 입력 스키마 검증과 비고객 응답의 의미 비교를 제공한다. 모든 `MATCH`는 해당 부분 검사 결과이며 실행 허가, 전체 preflight/post-call PASS 또는 실제 공격 차단 결과가 아니다.

## 진입점과 결과

모든 클래스는 `com.finsecseal.policy`에 있다.

| 파일·메서드 | 입력 | 성공·실패 전달 |
|---|---|---|
| `CatalogBoundInputSchemaEvaluator.evaluate` | `ApprovedPolicySource`, 원문 `ToolProposal` | `InputOutcome.MATCH`, `INVALID_REQUEST_SCHEMA`, `TOOL_NOT_IN_CATALOG` |
| `CatalogBoundOutputSchemaEvaluator.evaluate` | `runId`, `toolName`, 원문 응답 `JsonNode`, `actorId` | 기존 `OutputSchemaCheck`와 source binding, `MATCH` 또는 `ADAPTER_CONTRACT_FAILURE` |
| `NonCustomerResponseSemanticsEvaluator.caseContext` | 독립 서버 `PolicyBusinessContextFacts`, 응답 body | `Outcome.MATCH` 또는 `ADAPTER_CONTRACT_FAILURE` |
| `NonCustomerResponseSemanticsEvaluator.document` | 해당 호출의 `PolicyObjectScopeFacts`, `DocumentSource`, 응답 body | 같은 부분 결과 |
| `NonCustomerResponseSemanticsEvaluator.reviewNote` | `ApprovedPolicySource`, 해당 호출의 `PolicyObjectScopeFacts`, 응답 body | 같은 부분 결과 |

입력 평가기와 의미 비교기는 public 기본 생성자를 사용한다. 출력 평가기의 기존 `TestRunProjectionService`, `ReleaseService` 생성자와 오류 계약은 유지한다. 내부 `CatalogJsonSchemaValidator`는 입력·출력 평가기만 공유하는 package-private 엔진이다.

`InputSchemaException.code()`는 `INVALID_POLICY_SOURCE`, `INVALID_CATALOG_SCHEMA`, `SCHEMA_ENGINE_FAILURE`를 구분한다. 누락·추가 입력 스키마, 손상된 선택 스키마와 미지원 format은 요청자의 스키마 위반으로 바꾸지 않는다. `SemanticInputException.code()`는 잘못된 서버 기대값의 `INVALID_EXPECTED_CONTEXT`와 손상된 승인 정책의 `INVALID_APPROVED_SOURCE`를 구분한다. 예외에는 원문·검증 상세·owner 예외의 cause가 없다. 이러한 오류와 응답 격리는 운영 실패이며 보안 차단 성공으로 집계하지 않는다.

## 승인 출처와 입력 경계

`ReleaseToolCatalogContractAdapter.load(releaseId, actorId)`는 기존 A 조회 한 번의 normal/server snapshot에서 입력 스키마를 함께 추출한다. `SourceBoundCatalog.inputSchemas()`는 현재 일반 Tool 5개와 `LOAN_DECISION_UPDATE`의 전체 map이며 생성자와 accessor 모두 중첩 JSON을 복사한다. 기존 6·7·8·9인자 생성자는 유지하지만 입력 map이 비어 있으므로 새 입력 평가에는 사용할 수 없다. 별도 owner 조회·SQL·adapter 호출은 추가하지 않는다.

입력 평가는 policy allowlist 대신 이 전체 카탈로그를 사용한다. `LOAN_DECISION_UPDATE`의 정상 입력은 스키마 `MATCH` 뒤 기존 Human Boundary 판단으로 이어져야 한다. 현재 카탈로그에 없는 `EXTERNAL_HTTP`와 일반 미등록 Tool은 `TOOL_NOT_IN_CATALOG`이며 외부 전송 정책 판단 완료를 뜻하지 않는다.

요청 이름은 기존 C 카탈로그 식별자 형식 `[A-Z][A-Z0-9_]{1,99}`, arguments는 JSON object를 사용한다. 원문 이름·문자열·enum·숫자를 정규화하지 않는다. B의 기존 validation/registry를 대신 실행하지 않는다.

입력 한도는 UTF-8 32KiB 이하와 root를 1로 세는 깊이 32다. 깊이 숫자는 명세 고정값이 아닌 C 구현 선택이다. 복사·직렬화 전에 비재귀 순회로 깊이, 넓은 트리, 긴 키/문자열, 순환, 비JSON·비유한 값을 거절하고 이후 정확한 직렬화 바이트를 검사한다. 호출 중에는 입력을 변경하지 않아야 한다. 이미 parsed JSON에서 중복 object key를 복원했다고 주장하지 않는다. 배열 중복의 정책 검사는 기존 Facts/정책 경계에 남는다.

숫자는 정수 변환 전에 unscaled bit length와 decimal precision, `long`으로 계산한 예상 정수 자릿수를 제한한다. 자릿수 한도 32768 역시 C의 입력 작업량 제한 선택이다. 짧은 `1E+100000000`이 큰 정수로 확장되는 경로를 입력 단계에서 차단하며 반올림하지 않는다. 0은 정수 확장 예외지만 극단적 scale의 JSON 변환 성공을 보장하지 않는다. 이 제한은 기존 standalone 출력 평가기나 임의 JSON Schema 계산 전체의 CPU 상한을 보장하지 않는다.

## 출력 스키마와 독립 의미 비교

출력 평가기는 실제 A 스키마를 적용한다. 문서 유형 4개, 신뢰 라벨 2개, 검토 상태 2개를 정상 범위로 유지하며 스키마에 없는 nonblank 제한을 추가하지 않는다. 기존 정확한 숫자 비교, 전체 스키마 재검사, format assertion, 로컬 참조 제한과 source binding은 유지한다.

의미 비교의 기대값은 응답에서 채우지 않는다.

- Case: 서버의 case/applicant/stage를 정확히 비교하고 allowed document 집합을 비교한다. 응답 문서 순서·반복은 집합을 바꾸지 않으며 빈 목록도 허용한다. 이 equality 방식은 명세의 서버 문맥 원칙을 적용한 C 설계 해석이다.
- Document: 요청 Case와 현재 Case가 일치하는 단일 요청 문서를 사용한다. allowed 목록 및 저장 ownership과 동일 문서에 묶인 `DocumentSource(DocumentOwnership, sourceTrustLevel)`를 확인한 뒤 응답의 case/document/trust label을 비교한다. 두 정상 label 모두 저장값과 같으면 허용한다. 제출자와 신청자의 동일성을 요구하거나 문서 원문을 정제하지 않는다.
- ReviewNote: 요청·현재 Case를 확인하고 실제 승인 정책의 `outputPolicy.reviewStatusAllowed`에 응답 상태가 포함되는지 비교한다. 승인·정책 전체 검증을 재구현하지 않으며 reason/evidence의 추가 nonblank·요청 원문 동일성 조건을 만들지 않는다.

같은 호출에 결합된 서버 기대값과 동일 응답 snapshot으로 스키마·의미 검사를 함께 수행해야 한다. 이전 `OutputSchemaCheck.MATCH`에는 응답 digest가 없으므로 다른 응답의 검증 증명으로 재사용할 수 없다. `LOAN_POLICY_SEARCH`의 `TRUSTED_INTERNAL` 제약은 실제 스키마의 const가 처리하며 항상 MATCH인 별도 비교기를 만들지 않는다.

## 검증 범위와 이어질 연결

단위 테스트는 실제 A 스키마 6개, 정상 출력 범위, 경계 크기·깊이·숫자, source 오류, 원문 보존과 세 Tool의 같은-body schema/semantic 조합을 검사한다. 기존 PostgreSQL 테스트는 저장 manifest의 입력 스키마 6개와 대표 입력 4건을 기존 post-source 측정 구간에서 비교하며 source 감사 2건, 이후 추가 owner 호출·감사·검증 대상 도메인 변화 0과 `TOOL_REQUEST` 0을 유지한다. 이는 해당 구성 요소의 증거다.

C의 실제 Gateway는 이 검사와 기존 정책 단계를 조합하고 결정 저장 commit 뒤 실행 및 응답 전달 여부를 처리해야 한다. B의 `PolicyGateway` 호출, `ToolAdapter.execute`, `StateChangingToolExecutionService.execute`는 이미 공개되어 있으므로 실행 API 자체가 없다는 이유로 C 구현을 미루지 않는다.

실제 연동에는 인증된 실행 권한, Run/Case/namespace에 결합된 독립 문맥·실제 operation/registry 관찰값, 응답 classification 및 상태 변화/provenance가 필요하다. 현재 B `ToolExecutionResult(output, stateChanged)`만으로 이 정보를 증명할 수 없다. 비고객 분류를 임의 NORMAL로 채우거나 상태 변화가 없다고 가정하지 않는다. 현재 정상 Tool 중 CASE_CONTEXT_READ·DOCUMENT_READER·LOAN_POLICY_SEARCH·REVIEW_NOTE_WRITE의 실제 B adapter도 별도 구현이 필요하다. 전체 Gateway, BASELINE 안전 검증과 Replay 연결은 다음 C 작업이며 실제 모델 전달 0·상태 변화 폐쇄·D 판정/지표 연동은 이 기능의 완료 증거에 포함하지 않는다.
