# C 저장 계약 검토 조회

## 범위와 현재 연결 상태

원 [역할 분담](../FINSEC_SEAL_4인_역할분담.md)의 Contract diff·검토, [FS-06](predev/06_FUNCTIONAL_SPEC.md), [계약 명세](predev/12_SAFETY_CONTRACT_SPEC.md), [검토 UI 명세](predev/20_UI_UX_SPEC.md)를 위한 저장본 조회다. 축약 Preview API #31을 호출하거나 구현 기준으로 사용하지 않는다.

현재 A PR #33의 `ContractPersistenceService.find/list`를 사용한다. A가 workspace 권한과 저장 무결성을 확인하고, C가 저장본·기록된 기준 계약·기존 `SafetyContractReviewDiff`를 묶어 검토 자료를 만든다. 후보 생성, 저장, validate/approve/reject, 승인본 선택은 이 조회가 수행하지 않는다.

이 문서는 PR #33 반영 전 작성된 C handoff의 연결 상태를 갱신한다. A의 계약 저장·검증·승인·현재 승인본 조회와 적격 Finding 출처 조회는 이제 존재한다. 사용법은 [A 연결 문서](A_CONTRACT_INTEGRATION_HANDOFF.md)를 따른다. 이전 문서의 미완료 표현을 현재 API 부재로 해석하지 않는다.

## 보호된 추가 조회 API

`GET /api/v1/platform/contracts/{versionId}/review`

- 기존 A `ContractAccessFilter`가 검증한 `X-Contract-Reviewer-Key`와 서버 생성 `CONTEXT`만 사용한다. C가 인증 정보나 ReviewerContext를 만들지 않는다.
- A 설정 Actor를 사용하며, 다른 `X-Actor-Id` 또는 Cookie를 보내면 거절된다. 브라우저는 `credentials: omit`을 사용한다. 키를 bundle·Git·로그에 넣지 않는다.
- 성공은 기존 `{data, traceId, timestamp}` envelope와 `Cache-Control: no-store`를 반환한다. C 조회는 `ETag`를 제공하지 않는다. **`data.resourceHash`**는 A 변경 요청의 동시성 토큰이며, 요청마다 달라지는 envelope 전체의 캐시 검증자가 아니다.
- GET은 멱등성 예약·감사 기록·계약 상태를 만들거나 갱신하지 않는다. 별도 조건부 응답 처리나 HTTP 조건 무시 로직은 추가하지 않는다. 큰따옴표로 감싼 `data.resourceHash`를 `If-None-Match`에 보내도 이를 C 응답의 ETag로 취급하지 않는다.

**원 경로·인증 연결은 OPEN이다.** [원 API 명세](predev/10_API_SPECIFICATION.md)의 `/api/v1/contract-versions/{id}`와 session-cookie 인증을 이 추가 경로가 충족했다고 주장하지 않는다. A의 현재 보호 경로를 이용하는 통합용 조회다. 원 경로에 보호 없는 별칭을 만들거나 A 인증 필터를 변경하지 않았다.

`data`의 명시적 응답 필드:

| 필드 | 의미 |
| --- | --- |
| `identity` | 실제 저장 `versionId`, `workspaceId`, `releaseId`, `contractKey`, integer `version` |
| `state`, `policyHash`, `resourceHash` | 같은 조회 시점의 저장 상태와 hash |
| `storedPolicyJson` | **저장된 JSON 트리**를 직렬화한 문자열. LLM 원문이나 원래 요청의 공백·표기법이 아니다. A 저장 과정의 canonicalization을 되돌리지 않는다. |
| `canonicalPolicyJson` | 기존 C canonicalizer가 계산한 별도 canonical JSON 문자열 |
| `baseline` | 기록된 base hash에 대응하는 승인본의 `identity`, `policyHash`; 기록된 승인 기준이 없으면 `null` |
| `validation` | 저장된 proof의 `result`에서 가져온 `status`, `issues`; 저장된 검증이 없으면 `null` |
| `review` | 저장된 `actorId`, `role`, `comment`, `decision`만 제공; 없으면 `null`. session/credential metadata는 제외한다. |
| `changes` | `{pointer, kind, beforeJson, afterJson}` 목록. kind는 `ADDED`, `REMOVED`, `MODIFIED`. 전후 값은 JSON **문자열**, 없는 쪽은 `null`이다. |

큰 정수·Unicode·줄바꿈이 포함된 정책/변경 값을 브라우저의 일반 숫자로 다시 계산하지 않는다. 규칙 표가 필요하면 원본 JSON 문자열을 보존하면서 정밀도를 유지해 표시한다. 서버가 이미 계산한 `changes`를 사용하고 브라우저에서 hash나 diff를 재계산하지 않는다. 구조적으로 유효하지만 의미 검증이 INVALID인 정책도 검토할 수 있다. `validation`은 **저장된 검증 결과**이며 현재 Source에 대한 새 검증이나 승인 권한이 아니다. 제공되지 않은 승인 시각 등은 합성하지 않는다.

## 조회 일관성과 승인 연결

`StoredSafetyContractReviewService.review`는 실제 Spring proxy의 read-only REPEATABLE_READ transaction에서 A 조회를 묶는다. REQUIRED가 약한 외부 transaction을 그대로 상속하는 것을 막기 위해, A 호출 전에 actual transaction·read-only·정확한 isolation metadata를 검사한다. 메서드를 직접 호출하거나 READ_COMMITTED/쓰기 transaction 안에서 호출하는 것은 허용하지 않는다.

Target 식별자·workspace·정책의 정확한 contractId/양의 integer version·상태·hash를 검사하고 mutable JSON을 복사한다. `basePolicyHash == null`이면 기록된 승인 기준이 없다는 뜻이며 목록 조회 없이 기준 없는 비교를 제공한다. 승인 전에 후보를 여러 번 만들 수 있으므로 정수 version이 1이라는 뜻은 아니다. 값이 있다면 같은 workspace/release의 기록된 hash와 일치하는 다른 APPROVED 버전 하나가 필요하다. 최신 현재 승인본으로 대체하지 않으며, 이전 승인본도 비교 기준으로 사용한다. 기준 누락·중복·잘못된 출처·hash 오류를 최초 생성이나 변경 없음으로 표시하지 않는다.

조회 본문의 `data.resourceHash`를 큰따옴표로 감싸 A 변경 요청의 `If-Match: "<resourceHash>"`에 사용한다. A `:validate` 후에는 resourceHash가 바뀌므로 **검증 응답의 새로운 resourceHash**를 `:approve`/`:reject`에 사용한다. 변경 요청에는 A의 `Idempotency-Key` 규칙을 적용한다. 오래된 조회 본문의 resourceHash로 승인하면 409이며 상태를 바꾸지 않는다. 실패한 POST의 멱등성 응답 기록은 정상 동작이고, 조회 자체의 무변경 보장과 구분한다.

## 오류

C 처리 오류는 `application/problem+json`, 고정된 안전한 detail·instance, code·traceId·retryable·errors, `Cache-Control: no-store`를 반환한다. C의 명시적 오류 handler는 잘못된 UUID, 정책 원문, session, SQL 원인 또는 내부 예외를 응답에 넣거나 직접 로그로 출력하지 않는다. 통합 테스트의 로그 검증은 실제 시험한 기본 설정에 한정한다. 별도 Spring DEBUG·접근 로그 등 모든 운영 로그의 비노출을 보장하지 않으며, 이 작업에서 공통 로깅 설정은 변경하지 않는다.

| HTTP | code | 처리 |
| --- | --- | --- |
| 400 | `CONTRACT_REVIEW_INVALID_REQUEST` | UUID 오류; 서비스 호출 전 거절 |
| 409 | `CONTRACT_REVIEW_STORED_VERSION_INVALID` | 저장 식별자·상태·hash 불일치 |
| 409 | `CONTRACT_REVIEW_BASELINE_UNAVAILABLE` | 기록된 비교 기준을 안전하게 확인할 수 없음 |
| 503 | `CONTRACT_REVIEW_UNSAFE_TRANSACTION` | 일관된 조회 transaction이 아님; 자동 재시도 대상 아님 |
| 503 | `CONTRACT_REVIEW_UNAVAILABLE` | 비교·파싱·저장 조회 또는 transaction 경계 실패; 부분 성공 없음 |
| 403/404/409 등 | A의 기존 code | A 권한/존재/무결성 code와 HTTP 의미를 유지하며 detail은 고정 문구로 제한 |

A 필터의 자격 거절은 기존 `403 CONTRACT_AUTH_REQUIRED`다. 올바른 자격으로 다른 workspace를 읽으려 하면 A의 `403 OPERATOR_AUTH_REQUIRED`가 유지된다. C의 오류 처리는 이 controller에만 적용한다.

## 검증과 남은 작업

| 요구사항 | 검증 위치 |
| --- | --- |
| C-SC-001/002, FS-06: 식별자·기준 선택·정확한 JSON/diff·검증 표시 | `StoredSafetyContractReviewServiceTest`, 기존 `SafetyContractReviewDiffTest` |
| C-SC-003: 실제 저장 생명주기, 이전 승인본, 일관된 snapshot·무변경·안전한 rollback | `StoredSafetyContractReviewServiceIntegrationTest` |
| C-BND-001: 실제 A 인증·workspace·잘못된 ID·안전한 오류·응답 형식 | `StoredSafetyContractReviewControllerIntegrationTest` |
| TC-CON-005/006: 오래된 검토 resourceHash 거절·조회 무변경 | HTTP 통합 테스트와 기존 A 계약 통합 테스트 |

실제 PostgreSQL 테스트의 REMEDIATION 상태 준비는 B/D 실행 선행 조건을 공급하는 테스트 fixture다. 실제 공격·Oracle·Replay를 수행했다는 증거가 아니다. 단위 테스트의 transaction metadata 설정도 물리적 DB isolation 증거가 아니며, 별도의 실제 PostgreSQL 시험이 이를 확인한다.

HTTP 추가 후 실제 focused 실행은 139개 통과, 실패·skip 0개다. 서비스 단위 53개·PostgreSQL 10개·HTTP 16개·기존 diff 49개·A 계약 7개·A 패치 출처 4개를 포함한다. 전체 backend는 `FINSEC_AI_LIVE_E2E=false ./gradlew test --rerun-tasks`로 새로 실행해 1,609개 통과, 기존 외부 live-AI 시험 1개 skip, 실패 0개를 확인했다. AI는 기존 가상환경의 `python3 -m pytest -q`로 54개 통과했다. 이 결과는 실제 모델 호출을 포함하지 않는다.

하네스 Run ID는 `20260907T024847Z-5876a82c`다. 명령·종료 상태·JUnit XML·파일 hash·요구사항별 검증 위치와 최종 Supervisor/POST 판정은 로컬 `dev_harness/runs/<Run ID>/`의 append-only 검토 기록에 남긴다. 처음의 서비스 단위 테스트 준비/비교 실패 2건은 수정 후 통과했고, 별도의 전체 시험 DB SSL 초기화 실패 1건은 소스 변경 없이 재실행해 통과했다. 실패 기록은 삭제하지 않았으며 SSL 원인은 확정하지 않았다.

후속 C 검토 UI, 패치 입력·프롬프트·응답 연결, B의 실제 모델 provider·실행 연결, A의 패치 proposal 저장·적용 연결, D의 실제 결과·지표 연결은 별도 작업이다. 생성 전 draft 정보와 저장 후 실제 identity 결합도 현재 C/A 인터페이스에 맞춰 검토해야 하며, 명세가 요구하지 않은 UUID 선예약을 A의 필수 의무로 단정하지 않는다. 이 조회로 실제 Gateway ENFORCE·응답 격리·무실행/미전달 증거·controlled Replay가 완성됐다고 주장하지 않는다.

제출용 SIMULATED 화면은 유지한다. 원래 C 작업 순서를 따르고, FA-01·02·03은 이후 C의 정책 적용·차단/격리 검증 단계에서 다룬다. 공격 생성은 B, 실제 결과 판정은 D의 경계로 남긴다.
