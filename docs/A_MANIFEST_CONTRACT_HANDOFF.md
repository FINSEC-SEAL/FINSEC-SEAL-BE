# Role A Manifest 1.1 / C integration handoff

기준: `dev`의 C semantic validator `ec907559` / 병합 `51a91667`.
이 변경은 A의 Release 원천 모델을 제공한다. C의 production adapter, Contract 승인 및 Gateway enforcement는 C 소유다.

## 세 가지 계약 정합성 수정

| 문제 | Manifest 1.1 계약 |
|---|---|
| DOCUMENT_READER의 MIXED trust | 내부 Tool/adapter는 TRUSTED_INTERNAL, 본문 content는 `x-trust-level: UNTRUSTED`로 구분 |
| CUSTOMER_DATA_READ의 빈 output schema | 실제 B adapter 응답인 `rows[].fields` 아래에 incomeBand/employmentStatus/accountNumber의 string schema 선언 |
| LOAN_DECISION_UPDATE가 정상 Tool과 혼재 | `serverToolCatalog`에만 선언. `agentExecutable=false`, `executionBoundary=HUMAN_ONLY` |

정상 Tool은 5개, 각 버전은 `1.1.0`이다. 서버 정의는
`src/main/resources/release/loan-review-tool-catalog-1.1.json`에 고정한다.
Manifest validation은 schema/trust/metadata가 해당 정의와 일치해야 통과한다.
정상 Tool 정의와 server catalog를 클라이언트 요청만으로 확장할 수 없다.

DOCUMENT_READER의 `sourceTrustLevel`은 문서 출처다. Tool의 `trustLevel`과 구분하며,
문서 본문을 system instruction이나 trusted command로 취급하지 않는다.
`accountNumber`의 schema 존재는 접근 허용이 아니다. C 기본 Contract는 incomeBand/employmentStatus만 허용한다.

CUSTOMER_DATA_READ 입력 배열 상한 20, 출력 `status/rows/customerId/fields`는 현재 B 구현에 맞췄다.
LOAN_DECISION_UPDATE의 input/output는 B PR #21 `fa6671bf`의 mock adapter에 맞췄다.
CASE_CONTEXT_READ / DOCUMENT_READER / LOAN_POLICY_SEARCH / REVIEW_NOTE_WRITE의 구체 schema는
도메인 명세 기반의 A 카탈로그 계약이며, 이 변경이 그 Tool adapter의 실제 구현 완료를 뜻하지 않는다.

## 등록 및 조회

완전한 등록 fixture:
`src/test/resources/fixtures/valid-release-manifest-v1.1.json`.

1. Agent 생성 후 `POST /api/v1/agents/{agentId}/releases`에 fixture를 제출한다.
2. `POST /api/v1/releases/{releaseId}:validate`, `:analyze`로 검증한다.
3. C는 `GET /api/v1/releases/{releaseId}/tool-catalog` 또는 동일한
   `ReleaseService.toolCatalog(releaseId, actorId)`로 검증된 원천 데이터를 읽는다.

POST 요청의 `Idempotency-Key` 등 기존 공통 API 계약은 그대로 적용된다.
정책 통합용 Release는 fixture의 `release.version`을 Agent 내에서 유일하게 지정한다.

조회 응답 `data`:

```text
releaseId
manifestSchemaVersion = "1.1"
agentArtifactFingerprint
releaseFingerprint
serverToolCatalogHash
tools[]                 // 정상 실행 Tool schema/trust/metadata 5개
serverToolCatalog       // version + non-executable 고위험 Tool 목록
```

조회 전에 저장 artifact, 정상 Tool/RAG catalog, Manifest validation, fingerprint를 확인한다.
prompt 본문은 반환하지 않으며 내부 복호화 검증 접근은 기존 audit 경로에 기록한다.
조회 성공 자체는 Contract 승인이나 Release PASS를 의미하지 않는다.

## C에서 연결할 부분

`SafetyContractSemanticValidator.ContractValidationCatalog`로 변환한다.

- `enabledReleaseTools`: 응답 `tools[]`에서 정확한 name과 outputFields를 추출한다.
- CUSTOMER_DATA_READ의 field 추출 위치는 해당 Tool의
  `/outputSchema/properties/rows/items/properties/fields/properties`이다.
- 다른 Tool의 output property와 고객 정보의 field policy를 혼합하지 않는다.
- `highImpactToolNames`: 검증된 server catalog에서 `executionBoundary=HUMAN_ONLY`,
  `agentExecutable=false`인 이름을 얻는다.
- Tool trust/hash는 A 원천 metadata를 사용한다. C semantic core DTO는 trust를 보증하지 않으므로
  C의 integration preflight 및 PolicyToolTrustEvaluator/Gateway에 따로 연결한다.
- 카탈로그 부재·버전/해시 불일치·필드 부재를 빈 목록이나 추정값으로 대체하지 않는다.

`ManifestCatalogContractTest.catalogFrom`은 호환성을 보여주는 **테스트용 예시**다.
production adapter는 이 변경에 포함되지 않는다. 정상 Contract fixture는
`src/test/resources/fixtures/loan-review-safety-contract.json`이다.

## 고위험 catalog 저장 및 fingerprint

`serverToolCatalog`는 서버 정의와 일치하는 snapshot으로 Manifest JSON과
`TOOL_SCHEMA / server-tool-catalog` artifact에 저장한다. `release_tools`의 enabled 정상 Tool에는 넣지 않는다.
별도의 catalog component hash인 `serverToolCatalogHash`가 Agent/Release fingerprint에 포함되며,
Release diff에도 `/serverToolCatalog` 변화가 표시된다.

기존 Manifest/Artifact의 불변성 DB guard를 재사용하므로 새 Flyway migration은 필요하지 않다.
B가 추가 중인 V13 migration과 번호가 충돌하지 않는다.

## 기존 Release 호환성

- Manifest 1.0과 Tool 1.0.0의 검증 규칙·fingerprint는 유지한다.
- 1.1은 새 Tool 1.1.0 정의로 저장하므로 같은 이름/버전의 불변 catalog 충돌을 피한다.
- 기존 analyzed Release와 catalog를 갱신하지 않는다. 새 Release를 만들고 재검증한다.
- 1.0에 serverToolCatalog를 끼워 넣는 요청은 거절한다.
- 1.0 Release에 `/tool-catalog`를 요청하면 `MANIFEST_INVALID`로 거절한다.
  기존 자료를 1.1 정책에 호환되는 데이터로 자동 승격하지 않는다.
- 향후 1.1.0 또는 `loan-review-server/1.0` 정의는 변경하지 않고 새 버전으로 추가해야 한다.

## 검증

```bash
./gradlew test --tests 'com.finsecseal.release.ManifestCatalogContractTest' \
  --tests 'com.finsecseal.release.ReleaseToolCatalogIntegrationTest' \
  --tests 'com.finsecseal.release.ManifestValidationServiceTest' \
  --tests 'com.finsecseal.contract.SafetyContractSemanticValidatorTest'
./gradlew test
```

핵심 검증: 기존 hash 고정 벡터, v1.0/v1.1 DB 공존, 실제 저장 catalog → C semantic 검증,
고위험 Tool 정상 allowlist 편입 거절, field/trust/schema 위조 거절,
catalog artifact/fingerprint 변조 거절, prompt 미노출,
저장된 DOCUMENT_READER metadata의 C TOOL_TRUST stage 통과 및 본문 UNTRUSTED 유지.

실행 결과(2026-09-06, Java 21 / PostgreSQL 17.11 Testcontainers):

- 전체 회귀: 77 suites, 601 tests — 600 통과, 1 skipped, 실패/오류 0.
- 마지막 DB → C trust 검증 테스트 추가 후 관련 4 suites 재실행: 41 tests 전부 통과.
- 위 두 실행의 테스트는 중복되며 합산하지 않는다. 마지막 추가 테스트는 전체 회귀 실행 이후 별도로 검증했다.
- `git diff --check` 통과(기존 `gradlew.bat` 줄바꿈 변경 제외, 해당 파일은 수정하지 않음).

전체 Golden Flow 완료 판정은 C의 production adapter/승인/Gateway 연결과 B/D 통합 검증 후 진행한다.

## 팀 공유용 요약

> Role A 소유의 Manifest 원천 모델에서 세 가지 정합성 수정과 로컬 검증을 완료했습니다.
> Manifest 1.1에서 DOCUMENT_READER의 내부 Tool trust와 untrusted content를 구분하고,
> CUSTOMER_DATA_READ의 실제 응답 필드를 선언했으며, LOAN_DECISION_UPDATE는 일반 실행 Tool과 분리했습니다.
> 기존 Release/hash는 유지하고 새 버전 fixture와 무결성 검증된 tool-catalog 조회 경로를 제공합니다.
> 변경 병합 후 C는 이 원천 데이터를 semantic validator/Policy Gateway에 연결하고 fail-closed 통합을 검증해 주세요.
> C의 production 통합과 최종 Supervisor 판정은 이번 A 수정의 완료 범위에 포함하지 않습니다.
