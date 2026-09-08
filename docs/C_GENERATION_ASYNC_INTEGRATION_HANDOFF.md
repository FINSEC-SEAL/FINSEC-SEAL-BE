# A 연동용 계약·패치 생성 호출 계약

확인일: 2026-09-08. A는 인증·중복 요청 처리·비동기 접수·작업 상태 저장/조회를 맡고, C는 생성 입력·프롬프트·결정적 검증과 생성 서비스 연결을 맡는다. B의 모델 호출 어댑터와 A의 저장 서비스를 재사용한다. 이 문서는 **현재 호출 가능한 코드**와 **추가 구현/합의가 필요한 계약**을 구분한다.

## 1. 적용 커밋과 현재 준비 상태

| 구분 | 확인한 코드 | 상태 |
|---|---|---|
| 초기 계약 생성, A 저장/인증, 패치 출처·응답 검증 | BE `dev` [`88aacb2`](https://github.com/FINSEC-SEAL/FINSEC-SEAL-BE/tree/88aacb203bbf3dc5d18dc09f88f9c9fd457103ee) | dev 반영됨. 초기 생성 조합 서비스에는 아래 제한이 남음 |
| 패치 프롬프트·생성 서비스 | [`de3fffc`](https://github.com/FINSEC-SEAL/FINSEC-SEAL-BE/tree/de3fffc28ec001c858259d8a8505a4baa18b07c9), [PR #39](https://github.com/FINSEC-SEAL/FINSEC-SEAL-BE/pull/39) | 확인 시 OPEN, dev 미반영. 해당 변경 반영 후 worker에서 호출 가능 |
| 생성용 202 접수 → worker → 결과 저장/조회 | 위 두 코드 기준 | 아직 전체 연결되지 않음. Java 생성 결과는 Operation 응답이 아님 |

PR #31의 축약 API를 최종 구현 기준으로 삼지 않는다. [원 API 명세](predev/10_API_SPECIFICATION.md)의 `POST /releases/{id}/contracts:generate`는 `{templateKey}` → `202`, `POST /findings/{id}/patch-proposals`는 `{baseContractVersionId}` → `202 Operation`이다. 실제 경로에는 `/api/v1` 접두사가 붙는다. 아래 내부 메서드는 이 HTTP 요청을 직접 대체하지 않는다.

## 2. 패치 생성: 구현된 worker 진입점

파일: [`src/main/java/com/finsecseal/contract/SafetyContractPatchGenerationService.java`](https://github.com/FINSEC-SEAL/FINSEC-SEAL-BE/blob/de3fffc28ec001c858259d8a8505a4baa18b07c9/src/main/java/com/finsecseal/contract/SafetyContractPatchGenerationService.java#L44).

```java
public PatchGenerationResult generate(
    UUID findingId,
    UUID baseContractVersionId,
    SafetyContractLifecyclePolicy.ReviewerContext reviewer);
```

`PatchGenerationResult`는 `SafetyContractPatchGenerationService`의 nested type이다. Spring bean을 주입받아 호출한다. 생성 서비스와 기존 B 클라이언트는 `finsec.ai.enabled=true`일 때 등록된다. 비활성화 상태는 bean 자체가 없는 구성이고 요청별 생성 실패 응답이 아니다.

| 입력 | 타입·전달 기준 |
|---|---|
| `findingId` | 실제 저장된 Finding UUID |
| `baseContractVersionId` | 실제 저장된 기준 계약 **version UUID**. 정책의 `contractId` 문자열이나 정수 version과 다름 |
| `reviewer` | A가 인증한 서버 측 `ReviewerContext`. 요청 JSON의 인증 플래그로 만들지 않음 |

기존 [`SafetyContractLifecyclePolicy`](../src/main/java/com/finsecseal/contract/SafetyContractLifecyclePolicy.java)의 타입은 다음과 같다.

```java
record ReviewerContext(UUID workspaceId, String actorId, String role,
    String sessionId, boolean authenticated, boolean csrfVerified, boolean demoMode) {}
record VersionIdentity(UUID versionId, UUID workspaceId, UUID releaseId,
    String contractKey, int version) {}
record SourceBinding(UUID releaseId, String manifestSchemaVersion,
    String agentArtifactFingerprint, String releaseFingerprint, String serverToolCatalogHash) {}
```

A의 저장본 조회는 workspace·reviewer role·인증·CSRF·actor/session을 검증한다. 비동기 실행 시 사용할 서버 측 인증 정보의 보존·재검증 방식은 A에서 연결해야 한다. 사용자 제공 `X-Actor-Id`만으로 trusted reviewer를 만들 수 없다.

### 반환 타입과 정상 판단

`PatchGenerationResult`는 내부 Java 객체이며 HTTP/DB 직렬화 계약이 아니다. A가 필요한 필드를 명시적으로 매핑한다.

| accessor | 실제 타입 |
|---|---|
| `assessment()` | `SafetyContractPatchResponseProcessor.PatchAssessment` |
| `finding()` | `SafetyContractPatchProposalFacts.FindingSourceFacts` |
| `sourceRunId()`, `sourceCaseId()`, `oracleResultId()` | 각각 `UUID` |
| `baseIdentity()`, `baseState()` | `VersionIdentity`, `SafetyContractLifecyclePolicy.VersionState` |
| `basePolicyHash()`, `baseResourceHash()` | 각각 `String` |
| `catalogBinding()`, `analyzedAt()` | `SourceBinding`, `Instant` |
| `templateKey()`, `promptVersion()`, `promptDigest()` | 각각 `String` |
| `sourceEvidenceDigest()`, `redactedEvidenceDigest()` | 각각 `String` |
| `provider()`, `model()`, `latencyMs()` | `String`, `String`, `long` |

`assessment().candidate()`는 `SafetyContractPatchProposalFacts.ProposedPatch`, `assessment().decision()`은 같은 클래스의 `ProposalDecision`이다. 후보 필드는 `resultPolicy(), operations(), rootCause(), normalWorkflowImpact(), rollback()`이고, 판단 필드는 `status(), acceptedProposal(), issues(), narrowing(), semantic()`이다.

| `assessment().decision().status()` | 의미 | A의 후속 처리 |
|---|---|---|
| `PROPOSED` | 축소·정상업무 검증을 통과한 미저장 후보 | A 저장 서비스에서 현재 출처·기준 계약을 다시 읽고 재검증한 뒤 저장 |
| `NO_CHANGE_NEEDED` | 빈 operations, 기준 계약과 같은 정책/hash/version | 새 후보 version을 만들지 않고 판단 결과를 작업에 기록 |
| `INVALID` | 도메인 검증 실패, acceptedProposal 없음 | issues를 기록하고 유효한 패치로 저장하지 않음 |

이 세 값은 **검증 판단**이다. `PROPOSED` 반환만으로 저장·승인·작업 완료가 보장되지 않는다. 현재 결과에는 새 `patchProposalId`, 후보 version UUID, `operationId`가 없다. 원문 evidence·prompt input·원본 모델 응답도 보관하지 않는다. 모델 provider/model/latency는 보고된 메타데이터이며 실제 모델 실체를 인증하는 값은 아니다.

### 실패 전달

동기 Java 호출이 예외를 던진다. Future/callback이나 Operation 실패 상태를 직접 반환하지 않는다. 다음 nested exception의 `code()`를 구분해서 받을 수 있다.

| 예외 선언 클래스 / nested 예외 | code 값 |
|---|---|
| `SafetyContractPatchGenerationService.PatchGenerationException` | `INVALID_REQUEST`, `UNSAFE_TRANSACTION`, `SOURCE_UNAVAILABLE`, `MODEL_CALL_FAILURE`, `MODEL_RESPONSE_INVALID`, `PROCESSING_FAILURE` |
| `SafetyContractPatchGenerationSourceService.PatchGenerationSourceException` | `INVALID_REQUEST`, `UNSAFE_TRANSACTION`, `SOURCE_BINDING_INVALID`, `BASE_VERSION_INVALID`, `SOURCE_UNAVAILABLE` |
| `SafetyContractPatchPromptBuilder.PatchPromptException` | `INVALID_SOURCE`, `EVIDENCE_BINDING_MISMATCH`, `REQUEST_TOO_LARGE`, `PROMPT_BUILD_FAILURE` |
| `SafetyContractPatchResponseProcessor.PatchResponseException` | `INVALID_REQUEST`, `RESPONSE_TOO_LARGE`, `MALFORMED_RESPONSE`, `IDENTITY_MISMATCH`, `PROCESSING_FAILURE` |
| `SafetyContractGenerationSourceService.GenerationSourceException` | `INVALID_REQUEST`, `UNSUPPORTED_TEMPLATE`, `RELEASE_NOT_ANALYZED`, `SOURCE_BINDING_MISMATCH`, `UNSUPPORTED_PURPOSE`, `SOURCE_CONTENT_INVALID`, `SOURCE_UNAVAILABLE` |
| A의 `BusinessException` | `errorCode()` 사용. 출처/인증 실패는 보존되며, secret 검출은 `SECRET_DETECTED`로 전달 |

동일 code가 여러 단계에 있으므로 실패 기록에는 단계/예외 종류도 함께 매핑한다. B 호출 예외는 안전한 `MODEL_CALL_FAILURE`로 합쳐진다. 이 값만으로 timeout/429 여부나 재시도 가능 여부를 구별할 수 없다. C는 추가 재시도하지 않으며, B의 기존 transport가 timeout/retry를 담당한다. 원문 content나 임의 예외 메시지를 Operation 공개 응답에 그대로 싣는 계약은 제공하지 않는다.

### 트랜잭션과 저장 연결

생성 호출 스레드에 actual transaction **또는 transaction synchronization**이 있으면 `UNSAFE_TRANSACTION`이다. Worker 전체를 `@Transactional`로 감싸면 안 된다. C의 source Spring proxy가 짧은 쓰기 `REPEATABLE_READ` transaction에서 A 출처·기준 계약·Release를 읽고 끝낸 후 모델을 호출한다. 이때 기존 A 접근 감사는 commit되므로, 뒤의 모델 실패가 해당 감사를 되돌리지는 않는다.

A에는 이미 아래 내부 저장 메서드가 있다. 파일: [`platform/contract/ContractPersistenceService.java`](../src/main/java/com/finsecseal/platform/contract/ContractPersistenceService.java).

```java
public StoredPatch storePatch(UUID findingId, UUID baseVersionId,
    SafetyContractPatchProposalFacts.ProposedPatch candidate, ReviewerContext reviewer);
public record StoredPatch(UUID patchProposalId, Version candidate) {}
```

`PROPOSED`일 때 `result.assessment().candidate()`가 입력 타입에 맞는다. A는 저장 시 다시 출처·기준 계약·catalog를 읽고 C 판단을 실행한다. `NO_CHANGE_NEEDED`/`INVALID`를 이 메서드로 저장할 수 없다.

**남은 저장 계약:** 현재 `storePatch`는 생성 메타데이터·생성 당시 source/base/catalog 기대값을 받지 않고 `generation_model_meta_json`에 `{}`를 넣는다. 결과 accessor의 provider/model/latency, promptVersion/promptDigest, 원본/마스킹 evidence digest와 source/base/catalog 결합을 A 저장 입력으로 연결해야 한다. 생성 도중 출처가 바뀐 경우의 처리도 이 입력 계약에 포함해야 한다. C가 직접 SQL로 보충하지 않는다.

연결 순서는 A 작업 상태 기록 transaction 종료 → C 생성 호출 → A 결과 저장/작업 상태 반영 transaction이다. 마지막 후보 저장과 작업 결과 연결의 원자성·재시작 시 중복 처리 방식은 A에서 구현할 부분이며 현재 C 메서드가 보장하지 않는다.

## 3. 초기 계약 생성: 존재하는 메서드와 남은 C 작업

파일: [`src/main/java/com/finsecseal/contract/ContractCandidateGenerationService.java`](../src/main/java/com/finsecseal/contract/ContractCandidateGenerationService.java).

```java
@Transactional
public CandidateGenerationResult generate(
    UUID releaseId, String templateKey, String contractKey, String actorId);

public record CandidateGenerationResult(
    UUID releaseId, UUID workspaceId, String contractKey, int version,
    String promptVersion, String promptDigest, String provider, String model,
    long latencyMs, tools.jackson.databind.JsonNode policy,
    String validationStatus, List<SafetyContractSemanticValidator.Issue> issues,
    String canonicalPolicyHash, String canonicalPolicyJson) {}
```

`releaseId`는 분석된 실제 Release UUID, `actorId`는 서버가 확인해야 하는 actor 문자열, `contractKey`는 정책 식별 문자열(필수, 최대 100자)이다. `templateKey`가 null/blank이면 `loan-review/1`을 사용한다. source는 지원 템플릿·목적·Release binding을 검사하며 actor를 별도로 검증한다.

정상 반환의 `validationStatus`는 문자열 `VALID`, `WARN`, `INVALID`다. `issues`의 요소는 `Issue(String jsonPointer, String code, IssueSeverity severity, String message)`다. `VALID/WARN`은 canonical JSON/hash가 있고 `INVALID`는 두 canonical 필드가 null이다. 모두 미저장 판단이며 저장 상태 `VALIDATED`나 승인으로 간주하지 않는다.

이 메서드는 별도 오류 envelope를 만들지 않는다. 입력 오류 `BusinessException`, source의 `GenerationSourceException`, prompt의 `CandidatePromptException`, 응답의 `CandidateResponseException`, B의 호출 오류 등이 예외로 전파된다. `CandidatePromptException.code()`는 `INVALID_SOURCE/INVALID_IDENTITY/RELEASE_BINDING_MISMATCH/PROMPT_BUILD_FAILURE`, `CandidateResponseException.code()`는 `INVALID_REQUEST/RESPONSE_TOO_LARGE/MALFORMED_RESPONSE/IDENTITY_MISMATCH/PROCESSING_FAILURE`다. source code는 위 표와 같다. 기존 HTTP 공통 handler는 BusinessException을 ProblemDetail로 바꾸지만 C 전용 예외는 별도 매핑 없이 일반 INTERNAL_ERROR로 처리한다. 이것은 작업 상태 저장 계약이 아니다.

**이 조합 메서드는 최종 비동기 연결 완료로 인계하지 않는다.** 직접 JDBC로 workspace와 `max(version)+1`을 읽고 UUID를 만들며, 같은 `@Transactional` 안에서 모델까지 호출한다. A의 인증된 identity 할당/예약을 입력받는 계약이 없고 생성 UUID도 결과 DTO에 없다. 후보·Operation을 저장하지 않는다.

또한 [`ContractCandidateGenerationController`](../src/main/java/com/finsecseal/contract/ContractCandidateGenerationController.java)는 원 명세와 같은 `/releases/{releaseId}/contracts:generate` 경로에서 `{templateKey, contractKey}`와 `X-Actor-Id`를 받아 기본 `200 ApiResponse<CandidateGenerationResult>`를 반환한다. A가 새 202 controller를 추가할 때 이 기존 mapping과 충돌하지 않도록 교체를 조정해야 한다. 현재 `ContractAccessFilter`의 보호 prefix에 이 release 하위 경로가 없으므로, 공통 `IdempotencyFilter`가 존재한다는 사실만으로 생성 경로의 인증 선행을 보장하지 않는다.

이미 구현되어 재사용 가능한 C 구성요소는 다음과 같다. 새 worker 진입점은 아직 없으므로 아래를 새 메서드가 있는 것처럼 안내하지 않는다.

| 파일 / 메서드 | 입력 → 출력 |
|---|---|
| `contract/SafetyContractGenerationSourceService.prepare` | `(UUID releaseId, String templateKey, String actorId)` → `PreparedGenerationSource` |
| `contract/SafetyContractCandidatePromptBuilder.build` | `(PreparedGenerationSource, VersionIdentity)` → `CandidatePrompt` |
| `runtime/ai/ContractCandidateAiClient.generate` (B) | `(String promptVersion, String instructions, String inputJson)` → `CandidateModelResponse(String provider, String model, String content, long latencyMs)` |
| `contract/SafetyContractCandidateResponseProcessor.process` | `(CandidatePrompt, String content)` → `CandidateAssessment` (`policy()`, `validation()`, `canonicalPolicy()` 등) |

경로 접두사는 `src/main/java/com/finsecseal/`이다. **C 후속 작업은** A가 제공하는 인증된 workspace/identity 입력을 사용하고, 모델 대기에서 DB transaction을 분리하며, 생성 결과·실패를 worker에 일관되게 반환하는 조합 서비스 정리다. **A 후속 계약은** 생성용 contractKey/정수 version/identity의 할당·동시성 규칙과 결과 저장 입력이다. 기존 A `create(UUID releaseId, JsonNode policy, ReviewerContext reviewer) → Version`는 CANDIDATE 저장을 제공하지만 생성 전 identity 예약 API는 아니다.

## 4. 미구현/연동 필요 항목과 담당

| 담당 | 이미 있는 부분 | 남은 부분과 영향 |
|---|---|---|
| A | reviewer 인증, 공통 idempotency, 계약 저장·validate·approve, 패치 적격 출처 필터와 `storePatch` | 생성 경로 인증 선행, 202/작업 접수·worker·상태 조회 연결, identity 할당, 생성 결과/메타데이터 저장 계약. 완결된 생성 API에 필요 |
| C | 초기 source/prompt/response, 패치 source/response와 PR #39 생성 서비스 | 초기 생성 조합 서비스 정리. 합의된 A 입력/저장 계약에 맞춘 연결 검증 |
| B | 실제 `ContractCandidateAiClient` HTTP 경로, timeout/retry, OpenAI-compatible provider | 기본 deterministic provider는 정책 JSON을 반환하며 패치 5필드 envelope를 지원하지 않음. 이를 사용할 경우 B 수정 필요. 외부 모델의 실제 패치 생성은 별도 통합 확인 필요 |
| A/C | 위 Java 결과/예외 타입 | Operation 공개 DTO, 상태 이름, 검증 INVALID와 실행 예외의 매핑, 안전한 오류 code/retry 정책 확정·연결 |

패치 모델 content는 `resultPolicy/operations/rootCause/normalWorkflowImpact/rollback` 5필드 envelope여야 한다. B의 일반 후보 생성 transport가 없다는 뜻이 아니다. 기존 A/D 출처 필터도 이미 있으므로 미구현 선행 조건으로 다시 요청하지 않는다.

Operation 설계 시 **제안하는 구분**은 수행 상태와 검증 판단을 별도로 기록하는 것이다. 예를 들어 `INVALID`는 검증이 끝난 결과이고 transport/parse/engine 예외는 수행 실패다. 이는 현재 구현된 Operation enum/응답 schema가 아니다. `PROPOSED`도 A 결과 저장이 실패했다면 저장 완료로 표시할 수 없다.

## 5. 검증 근거와 이후 요청 양식

이번 문서는 위 커밋의 코드와 테스트 assertion을 읽어 대조했다. 제품 코드 수정이나 새 테스트 실행은 하지 않았다. PR #39의 `SafetyContractPatchGenerationServiceTest`, `SafetyContractPatchPromptBuilderTest`, `SafetyContractPatchGenerationServiceIntegrationTest`에는 3종 판단, 안전한 예외, 활성 transaction 거절, 설정에 따른 bean 등록, 실제 Spring/PostgreSQL source transaction 종료 후 B client의 loopback HTTP 호출, 금지 출처/secret의 미전송 검사가 있다. 이것을 외부 LLM 실행·Operation 영속화·승인·공격 차단 완료의 근거로 확대하지 않는다.

이후 A/B/D 연동 요청에는 아래 양식을 채운다. 구현 전 제안 signature는 반드시 **미구현 제안**으로 표시한다.

```text
대상 기능 / 소유자:
기준 repository / branch / commit / PR / dev 반영 여부:
호출 파일 / 클래스 / 메서드(정확한 signature):
입력 타입 / 필드 의미 / 서버가 확보할 인증·출처:
반환 타입 / 정상 판단 / 저장 결과 ID 유무:
실패 예외·code / HTTP·Operation 매핑 유무 / 재시도 주체:
호출 순서 / transaction·설정 전제:
구현 완료 / 아직 미구현 / 요청받는 소유자가 추가할 계약:
검증 코드 또는 실행 근거 / 아직 확인하지 않은 통합:
```
