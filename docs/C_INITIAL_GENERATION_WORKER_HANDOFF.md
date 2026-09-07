# 초기 계약 생성 worker 연동

2026-09-08 구현. BE `feat/c-contract-generation-worker`, 기준 `dev` `7a78a65`(PR #39·#40 머지 포함). 초기 생성에 관한 이전 인계의 "C worker 미구현" 설명은 이 문서로 갱신한다. A의 인증·중복 요청·비동기 접수·상태 저장/조회 구현과 C 생성·검증 구현은 구분한다.

## 호출 파일·입력

파일: [`src/main/java/com/finsecseal/contract/ContractCandidateGenerationService.java`](../src/main/java/com/finsecseal/contract/ContractCandidateGenerationService.java).

```java
CandidateGenerationResult generate(
    SafetyContractLifecyclePolicy.VersionIdentity identity,
    String templateKey,
    String actorId);
```

Spring bean을 주입받아 내부 worker에서 호출한다. 서비스와 기존 B HTTP 클라이언트는 `finsec.ai.enabled=true`에서 등록된다. false이면 worker bean이 없다. Future/callback/Operation을 반환하는 API가 아니라 A의 비동기 worker 안에서 호출할 동기 Java 메서드다.

| 입력 | 실제 계약 |
|---|---|
| `identity` | 기존 `VersionIdentity(UUID versionId, UUID workspaceId, UUID releaseId, String contractKey, int version)` |
| UUID 세 필드 | 모두 nonnull. A가 확인한 실제 workspace/Release를 사용 |
| `contractKey` | nonblank, 앞뒤 공백 없음, Java `String.length()` 기준 최대100. 정책 JSON의 `contractId` 문자열 |
| `version` | 양수 `int`, `Integer.MAX_VALUE` 포함 |
| `templateKey` | null/blank이면 `loan-review/1`; 다른 지원되지 않는 값은 거절 |
| `actorId` | A가 인증한 서버 actor. nonblank, 앞뒤 공백 없음, `String.length()` 최대120 |

**호출 전에 A가 Release/workspace 접근을 인증·인가해야 한다.** 형식이 맞는 identity/actor는 권한 증명이 아니다. C는 SQL 조회, `max(version)+1`, UUID 할당 또는 예약을 수행하지 않는다. 입력 `versionId`는 생성 시점의 식별 정보이며 저장됐다는 뜻이 아니다. 새 UUID 예약 테이블을 요구하지 않으며, 기존 A `create(...)`가 별도로 만든 저장 version UUID와 혼동하지 않는다. 저장 시 실제 ID와 생성 결과의 연결은 A가 보존한다.

Worker의100 제한은 기존 생성 서비스 및 A `ContractPersistenceService.create`의 저장 제한을 유지한다. 독립 `SafetyContractCandidatePromptBuilder`의200 제한은 변경하지 않았다. 이 worker에서200까지 허용한다고 해석하지 않는다. identity의 Unicode·줄바꿈·정수 값은 정규화하거나 다시 할당하지 않는다.

## 반환값과 정상 판단

반환 타입은 `ContractCandidateGenerationService.CandidateGenerationResult`다. private constructor와 accessor를 가진 불변 내부 객체이며 HTTP 직렬화/DB 저장 명령이 아니다. A는 필요한 필드를 명시적으로 매핑한다.

| accessor | 타입·의미 |
|---|---|
| `identity()` | 입력 그대로의 `VersionIdentity` |
| `catalogBinding()` | `SafetyContractLifecyclePolicy.SourceBinding`: releaseId, manifestSchemaVersion, agentArtifactFingerprint, releaseFingerprint, serverToolCatalogHash |
| `analyzedAt()`, `lifecycleState()` | `Instant`, `ReleaseLifecycleState`; 생성 입력을 준비한 시점의 Release 상태 |
| `templateKey()`, `promptVersion()`, `promptDigest()` | `String`; digest는 정확한 UTF-8 `[promptVersion,instructions,inputJson]` 배열의 SHA-256 |
| `provider()`, `model()`, `latencyMs()` | `String`, `String`, `long`; provider/model은 각각 최대80/120 Unicode code point의 nonblank 값, latency는 비음수 |
| `policy()` | `tools.jackson.databind.JsonNode` 방어적 복사 |
| `validation()` | `SafetyContractSemanticValidator.ValidationResult(status, issues)` |
| `canonicalPolicy()` | `Optional<SafetyContractCanonicalizer.CanonicalPolicy>`: canonicalJson, policyHash |

`validation().status()`는 `VALID / WARN / INVALID`다. VALID/WARN에는 canonical 결과가 있고 INVALID에는 없다. issues 요소는 `Issue(jsonPointer, code, severity, message)`이며 목록은 변경할 수 없다. 현재 금융 검증기는 WARN을 만들지 않지만, 반환 계약은 WARN을 지원한다.

이는 미저장 검증 결과다. CANDIDATE/VALIDATED/APPROVED 저장 상태나 승인 권한으로 취급하지 않는다. `operationId`나 새 저장 version UUID도 생성하지 않는다. 결과에는 raw prompt/source/model envelope를 보관하지 않는다. provider/model은 보고된 값이며 모델 실체에 대한 인증은 아니다.

## 실패와 트랜잭션

호출은 예외로 실패를 전달한다. `CandidateGenerationException.code()`는 다음과 같다.

| code | 의미 |
|---|---|
| `INVALID_REQUEST` | identity/actor 형식 오류; source 읽기 전 거절 |
| `UNSAFE_TRANSACTION` | 호출자 transaction 또는 synchronization 존재, source/프롬프트 처리 후 남은 transaction |
| `SOURCE_UNAVAILABLE` | source의 예기치 않은 오류 또는 null 반환 |
| `REQUEST_TOO_LARGE` | B 요청의 문자 수/직렬화 크기 제한 초과; 전송 전 거절 |
| `MODEL_CALL_FAILURE` | B 모델 호출의 RuntimeException을 안전하게 통합한 오류 |
| `MODEL_RESPONSE_INVALID` | null 모델 envelope 또는 잘못된 provider/model/latency |
| `PROCESSING_FAILURE` | 예기치 않은 프롬프트·입력 검사·응답 엔진 오류 또는 null 결과 |

기존 `GenerationSourceException`, `CandidatePromptException`, `CandidateResponseException`의 `code()`는 유지한다. 예: 지원하지 않는 템플릿은 `UNSUPPORTED_TEMPLATE`, 출처 Release 불일치는 `RELEASE_BINDING_MISMATCH`, 응답 파싱/identity 실패는 `MALFORMED_RESPONSE/IDENTITY_MISMATCH`, 과대 응답은 `RESPONSE_TOO_LARGE`다. 입력 비밀정보 검사에서 A `BusinessException.errorCode()==SECRET_DETECTED`도 유지한다. 비밀정보 검사에는 기존 A redactor를 사용하며, schema/identity/model 입력이나 prompt digest를 마스킹 결과로 덮어쓰지 않는다.

`INVALID`는 검증 판단이며 위 실행 예외와 다르다. C의 새 예외는 고정 메시지, 원인 없음, suppressed 비활성이다. B의 timeout/retry/transport는 기존 클라이언트가 담당하고 C는 추가 재시도하지 않는다. `MODEL_CALL_FAILURE`만으로 timeout/429 또는 재시도 가능 여부를 구분할 수 없다. 공개 HTTP/Operation 오류 코드와 재시도 정책은 A가 연결할 부분이다.

호출자 transaction **및 synchronization 밖**에서 실행해야 한다. A가 작업 시작 상태를 저장한 transaction을 끝낸 다음 C를 호출한다. 기존 `SafetyContractGenerationSourceService`의 Spring proxy가 짧은 쓰기 transaction으로 출처를 준비하고 끝낸 후 모델을 호출한다. 초기 source의 기존 isolation 계약은 유지하며 patch source의 REPEATABLE_READ와 혼동하지 않는다. source 접근 감사는 이후 모델 실패에도 남을 수 있다. 생성 후에는 A의 별도 transaction에서 source/identity를 재확인하고 결과와 작업 상태를 저장한다.

## 구현된 부분과 남은 연결

- **C 구현됨:** 위 worker, source/prompt/response 재사용, 모델 호출 전 transaction·입력 크기·비밀정보 검사, 불변 판단·메타데이터와 안전한 오류 전달.
- **기존 C 동기 API 제거:** `ContractCandidateGenerationController`의 `POST /api/v1/releases/{releaseId}/contracts:generate` → 200 응답을 제거했다. 원 명세 경로에서 A의202 접수를 추가할 때 중복 MVC mapping이 생기지 않는다. A의202/Operation 구현이 이 변경으로 생기는 것은 아니다.
- **A 연결 필요:** 인증·인가 후 호출, contractKey/정수 version/identity의 할당과 동시성 규칙, 멱등 접수·worker·상태 조회, 생성 시점 source binding과 저장 시점 재검증, 모델/prompt 메타데이터 및 실제 저장 ID 연결. 기존 `ContractPersistenceService.create(UUID releaseId, JsonNode policy, ReviewerContext reviewer)`의 후보 저장은 재사용할 수 있다.
- **B:** 기존 `ContractCandidateAiClient.generate(promptVersion,instructions,inputJson)` → `CandidateModelResponse(provider,model,content,latencyMs)`를 호출한다. 별도 Agent Run이나 새 모델 transport는 추가하지 않는다.

이후 연동 요청에도 기준 branch/commit/PR, 파일·정확한 signature, 입력/출력, 정상 판단/실패, transaction·설정 전제, 구현 여부와 담당별 남은 계약을 함께 전달한다.

## 검증 범위

새 단위57개·실제 Spring/PostgreSQL 및 loopback HTTP 통합10개가 통과했다. TC-CON-001/002/003, 원문 identity·hash,100/101 및 최대 int, 불변 결과, safe failure, secret 미전송, caller-thread transaction/resource 해제, 독립 연결의 Release 잠금 획득과 감사 commit,20개 도메인 테이블 무변경, AI 활성 상태의 worker 존재·기존 MVC 경로 부재를 확인했다. 전체 명령·XML·최종 파일 hash는 하네스 Run `20260907T194053Z-139e4e36`에 보존한다.

외부 LLM 실행, A의 Operation/후보 영속화 전체 흐름, Gateway·Replay 또는 공격 차단 완료를 이 테스트로 주장하지 않는다.
