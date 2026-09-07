# C 계약 후보 준비·검증 및 리뷰 비교 인계

> 2026-09-08 생성 연동 정보는 [A 연동용 계약·패치 생성 호출 계약](C_GENERATION_ASYNC_INTEGRATION_HANDOFF.md)을 먼저 확인한다. 정확한 파일·메서드·입출력·예외·transaction 조건, PR #39의 dev 미반영 여부와 남은 담당별 연결을 구분했다. 아래 구현 설명과 테스트 수치는 최초 C 구성요소 작업의 기록이다.

원 명세의 `Manifest + Purpose + Tool Schemas + Financial Template → LLM Candidate → Deterministic Validator → Reviewer Approval` 흐름에서 C가 독립적으로 구현할 수 있는 생성 입력, 프롬프트, 응답 판단과 리뷰 비교를 다룬다. 실제 모델 호출·후보 저장·승인·ENFORCE·Replay·UI 전체 완료를 뜻하지 않는다.

기준은 [역할 분담](../FINSEC_SEAL_4인_역할분담.md), [현재 아키텍처](A_ARCHITECTURE_BASELINE.md), [Safety Contract 명세](predev/12_SAFETY_CONTRACT_SPEC.md), FS-06과 [원 API 명세](predev/10_API_SPECIFICATION.md)다. #31의 축약 Preview API를 호출하거나 해당 API의 범위를 새 구현 기준으로 사용하지 않는다. 기존 schema/semantic/canonical/lifecycle 판단은 재사용한다.

## 구현 진입점

| C 진입점 | 실제 동작 | 반환값이 보장하지 않는 것 |
|---|---|---|
| `LoanReviewFinancialTemplate.policyRules()` | 원 명세 `loan-review/1`의 정상 도구 5개, 필드 2개, 정상 상태·단계와 최대 권한 제한을 제공한다. 반환 JSON은 독립 복사본이다. | 계약 ID·정수 버전 할당, 저장 상태, 생성·검증·승인 |
| `SafetyContractGenerationSourceService.prepare(releaseId, templateKey, actorId)` | 분석된 실제 Release의 검증된 catalog를 한 번 읽고, 같은 쓰기 transaction의 Release 잠금 아래에서 정책 관련 Manifest 필드 7개를 복사한다. ID·schema·artifact/release fingerprint·목적·분석 상태를 확인한다. | 호출자의 인증·workspace 접근 권한, 후보 생성, 계약 저장·승인 |
| `SafetyContractCandidatePromptBuilder.build(source, identity)` | 호출자가 제공한 기존 `VersionIdentity`와 source Release를 결합한다. 고정 지시문과 실제 입력 JSON을 분리하고 정확한 프롬프트 digest를 계산한다. | A의 identity 예약·workspace 소유권, B의 모델 호출·응답 출처 |
| `SafetyContractCandidateResponseProcessor.process(prompt, content)` | 응답을 엄격하게 파싱하고 원본 계약 ID·정수 버전을 확인한 뒤 기존 결정적 검증기를 실행한다. INVALID에는 canonical 결과가 없다. ERROR 없는 VALID/WARN만 canonical JSON/hash를 가진다. | 저장된 VALIDATED 상태, `ValidationProof`, Reviewer 승인, 현재 Release와의 재대조, 실행 권한 |
| `SafetyContractReviewDiff.compare(before, after)` | 제공된 정책의 원본 값과 정렬된 set 배열을 비교하고 각 정책 hash를 별도로 계산한다. 최초 후보의 없는 baseline은 명시적으로 구분한다. | 인증된 저장본 조회·무결성 증명, 실행 가능한 typed patch, 변경의 안전성·승인 |

`before`는 `Optional<JsonNode>`다. 비교는 구조적으로 유효하고 canonicalize 가능한 정책을 대상으로 한다. 정상업무 권한 누락이나 권한 확대처럼 의미적으로 잘못된 정책도 리뷰어에게 차이를 보여준다. 구조/정규화 실패는 비교 불가 오류이며 빈 변경 목록으로 바꾸지 않는다. 기존 `SafetyContractNarrowingValidator`의 실행 가능한 축소 패치 검증과 별개다.

## 입력과 결과의 경계

생성 source는 `businessPurpose`, `businessWorkflow`, `humanApprovalBoundaries`, `runtimeContextRequirements`, `networkRequirements`, `tools`, `serverToolCatalog`를 보존한다. 도구의 실제 schema·설명·trust/classification metadata가 포함된다. root `systemPrompt`, 문서, Finding은 내보내지 않는다. A의 기존 검증 과정과 prompt 접근 감사 기록은 유지하며, provider 호출을 이 transaction 안에 넣지 않는다.

`VersionIdentity`는 기존 lifecycle 타입을 사용하며 ID를 임의로 만들거나 기본 버전을 넣지 않는다. 정확한 `contractKey`와 정수 version을 사용하고 Unicode NFC·줄바꿈으로 owner identity를 바꾸지 않는다. 이 값이 실제로 예약되었고 접근 가능한지는 A의 인증된 호출 경계가 확인해야 한다.

프롬프트 버전은 `loan-review-candidate/1`이다. 지시문에는 원본 설명을 삽입하지 않고 JSON 데이터로 전달한다. 프롬프트 digest는 정확한 UTF-8 JSON 배열 `[promptVersion, instructions, inputJson]`의 SHA-256이다. 여기서 `inputJson`은 다시 정규화하지 않은 문자열이다. 이 digest는 canonical policy hash, Release fingerprint, provider 호출 영수증과 다른 값이다. B는 고정 지시문과 입력 데이터의 구분을 실제 provider 요청에서도 유지해야 한다.

응답 처리기는 공유 ObjectMapper를 바꾸지 않는다. 단일 JSON object만 허용하며 중복 key, 추가 JSON/후행 token, Markdown fence, comment와 비표준 숫자를 거절한다. 자체 자원 제한은 UTF-8 65,536 bytes, 깊이 32, 문자열 8,192자, key 256자, 숫자 100자, token 16,384개다. 이 값들은 구현상의 입력 한도이며 금융 정책 규칙은 기존 validator가 담당한다. 자르기·복구·재시도·템플릿 대체는 수행하지 않는다.

결과는 원본 정책을 보존한다. Canonical JSON이 Unicode나 줄바꿈을 정규화하더라도 원본 identity를 덮어쓰지 않는다. 비교도 정확한 원본 문자열·정수를 사용하므로 canonical hash가 같아도 원본 변경은 보일 수 있다. 배열 순서만 다른 경우는 변경으로 표시하지 않는다. 결과 JSON 접근은 복사본이며 기본 `toString`과 처리 오류에 원문을 넣지 않는다. 검증/정규화 엔진 오류는 INVALID 정책으로 가장하지 않고 별도 처리 실패로 반환한다.

## 소유자 연결 상태 갱신

최초 작성 당시의 미구현 목록은 현재 상태와 달라 교체했다. BE `dev` `88aacb2`에는 A의 인증된 계약 저장·검증·승인과 패치 출처 필터, B의 실제 후보 생성 클라이언트가 있다. C 패치 생성 조합 서비스는 PR #39 `de3fffc`에 구현되어 있으며 2026-09-08 확인 시 dev 미반영이다.

A가 담당할 생성용 인증·중복 요청·비동기 접수·상태 저장/조회와 C가 정리할 초기 계약 생성 조합 서비스, A 생성 identity/메타데이터 저장 계약은 [새 인계 문서](C_GENERATION_ASYNC_INTEGRATION_HANDOFF.md)에 명시한다. 이미 있는 저장·모델 클라이언트·출처 필터를 다시 미구현으로 요청하지 않는다. 생성 판단과 저장된 VALIDATED/APPROVED 상태는 계속 구분한다.

Gateway 실행·Replay·D 판정의 완료 여부는 생성 진입점 인계와 별도다. 이 문서의 후보 검증 테스트를 해당 runtime 통합 완료의 증거로 사용하지 않는다.

## 검증과 하네스 증거

하네스 Run은 `20260907T003613Z-c5df85d1`이다. workspace의 `dev_harness/runs/<RUN_ID>/checkpoint_log.md` 및 각 checkpoint에 독립 Supervisor 판단을 append-only로 보존한다. 명령·exit code·JUnit XML·파일 SHA-256도 같은 Run에 보존한다.

검증된 source/template 91개, prompt 31개, response 64개 사례가 계약 회귀 실행에 포함되어 있다. Source 통합 13개는 실제 PostgreSQL 17.11/Spring transaction에서 양방향 잠금 대기, 변조 검증 실패, 감사 유지와 domain state 불변을 검사한다. 단위 테스트의 A 모의 서비스나 합성 모델 응답을 실제 A 인증·모델 호출 증거로 계산하지 않는다.

2026-09-07 마지막 계약 회귀 실행은 546개, 실패·오류·skip 0개로 통과했다. 리뷰 비교 49개를 포함한 수이며 앞의 개별 수와 중복 합산하지 않는다. `review_contract_tests.log`, `review_contract_summary.json`, `review_contract_junit/`에 명령과 결과·hash를 보존한다. 7종 set 배열은 모두 2개 이상의 값으로 순서 무관성을 검증하고, 권한 확대·정상업무 축소·큰 정수·원본 Unicode 변경·없는 baseline·안전한 실패를 검사한다.

전체 C 완료는 별도 owner 통합 증거가 필요하다. 이전 Run `20260906T171355Z-5116aa38`의 실제 enforcement/quarantine 및 operational-error accounting FAIL/BLOCKED는 이 단위 테스트로 닫지 않는다. 최종 인수에는 정확한 마지막 파일의 Supervisor 승인과 `harness post --run <RUN_ID> --with-agents` 통과가 필요하다.

재검증 명령:

```sh
./gradlew test --tests 'com.finsecseal.contract.*' --rerun-tasks --no-build-cache
./gradlew test
```

작업 브랜치는 `feat/c-contract-candidate-generation`이며 기존과 같은 `feat(contract): 한국어 기능 요약` 형식으로 기능별 커밋을 남긴다. 기존 사용자 `gradlew.bat` 변경은 포함하지 않는다.
