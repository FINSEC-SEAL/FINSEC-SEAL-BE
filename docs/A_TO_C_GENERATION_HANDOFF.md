# A → C: 비동기 계약·패치 생성 연결 계약

작성일: 2026-09-08. 기준 BE dev `1c9bb84`에는 C의 초기·패치 생성 worker가 모두 있다. A 작업 브랜치는 `codex/a-generation-operations`다. [설계 결정](A_GENERATION_ASYNC_DESIGN.md)과 실제 코드를 함께 기준으로 사용한다.

## C에 전달할 결론

**C의 현재 생성 메서드를 유지한다.** A가 접수·인증·identity 예약·worker 호출·원본 재검증·후보/메타데이터 저장·상태 조회를 연결했다. C는 별도 controller, Operation 테이블, SQL 저장 또는 worker 전체 transaction을 추가하지 않는다.

### 실제 호출 메서드

아래 파일의 공통 접두사는 `src/main/java/com/finsecseal/`이다.

| 파일·메서드 | A가 전달하는 입력 | C 반환값 |
|---|---|---|
| `contract/ContractCandidateGenerationService.generate(VersionIdentity identity, String templateKey, String actorId)` | 예약된 version UUID/workspace/Release/contractKey/정수 version, template, 인증된 actor | `CandidateGenerationResult` |
| `contract/SafetyContractPatchGenerationService.generate(UUID findingId, UUID baseContractVersionId, ReviewerContext reviewer)` | 적격 Finding, 최신 base **version UUID**, 인증된 서버 reviewer | `PatchGenerationResult` |

`platform/generation/CGenerationAdapter.java`가 반환값을 아래 A 타입으로 명시적으로 매핑한다. C 결과 객체를 그대로 HTTP/DB JSON으로 직렬화하지 않는다. C 반환 필드가 바뀌면 이 adapter와 연동 테스트를 함께 갱신한다.

## A worker 입력·출력

파일: `platform/generation/GenerationContract.java`, `GenerationEngine.java`.

```java
boolean GenerationEngine.available(Kind kind);
Generated GenerationEngine.generate(Work work);

record Work(UUID operationId, UUID claimToken, Kind kind,
    VersionIdentity identity, String templateKey,
    ReviewerContext reviewer, Source expectedSource) {}

record Generated(String outcome, JsonNode policy, ProposedPatch patch,
    Source observedSource, Metadata metadata, JsonNode issues) {}

record Metadata(String templateKey, String promptVersion, String promptDigest,
    String provider, String model, long latencyMs,
    String sourceEvidenceDigest, String redactedEvidenceDigest) {}
```

이 타입은 내부 Java 계약이며 HTTP 입력이 아니다. 프론트가 Work/reviewer/identity를 만들어 보내지 않는다.

- 초기 결과: `policy`는 C 생성 정책, `patch=null`, outcome은 VALID/WARN/INVALID.
- 패치 결과: `patch`는 C의 `assessment().candidate()`, `policy=null`, outcome은 PROPOSED/NO_CHANGE_NEEDED/INVALID.
- observedSource는 **생성 때 읽은 실제 값**을 사용한다. expectedSource를 그대로 복사해서 검증을 대신하지 않는다.
- provider/model/latency는 보고된 메타데이터이며 실제 모델 실체를 인증하지 않는다.
- 원문 prompt/inputJson/모델 응답 문자열, API key/cookie/CSRF token은 저장·공개하지 않는다.

정확한 출처 비교 필드:

```java
record Source(SourceBinding catalog, Instant analyzedAt,
    UUID findingId, UUID baseVersionId, String baseState,
    String basePolicyHash, String baseResourceHash, FindingSourceFacts finding,
    UUID sourceRunId, UUID sourceCaseId, UUID oracleResultId) {}
```

초기는 catalog/analyzedAt 외에 null이다. 패치는 모든 필드를 실제 출처에서 얻는다. 초기 identity는 입력과 반환의 완전 일치를 요구한다. 패치는 A가 base.version+1을 예약하고, 저장할 정책의 contractId/version을 예약과 대조한다.

## HTTP 계약

원 명세의 두 생성 경로를 사용한다. 공통 응답은 `{data,traceId,timestamp}`다.

```http
POST /api/v1/releases/{releaseId}/contracts:generate
Idempotency-Key: <request-key>
X-CSRF-Token: <csrf-token>
Content-Type: application/json

{"templateKey":"loan-review/1"}
```

```http
POST /api/v1/findings/{findingId}/patch-proposals
Idempotency-Key: <request-key>
X-CSRF-Token: <csrf-token>
Content-Type: application/json

{"baseContractVersionId":"<version UUID>"}
```

인증은 기존 reviewer session cookie와 mutation CSRF다. Cookie 없는 서버/CLI 요청은 `X-Contract-Reviewer-Key`를 사용할 수 있다. X-Actor-Id나 body의 role/workspace는 권한 근거가 아니며, body의 추가 필드를 거절한다.

두 요청 모두 DB 접수 commit 뒤 `202 Accepted`와 `Location: /api/v1/operations/{operationId}`를 반환한다. data 예시:

```json
{
  "operationId":"<UUID>", "kind":"CONTRACT", "status":"QUEUED",
  "statusUrl":"/api/v1/operations/<UUID>", "releaseId":"<UUID>",
  "outcome":null, "result":null, "errorCode":null, "errorStage":null,
  "retryable":false, "createdAt":"<UTC timestamp>", "startedAt":null, "finishedAt":null
}
```

`GET /api/v1/operations/{operationId}`는 같은 형태로 최신 상태를 반환한다. 인증된 workspace와 actor 소유 작업만 조회하며, 다른 작업은 404다. 구현된 DTO는 `GenerationContract.Operation`이다.
같은 Idempotency-Key·actor·workspace·path·내용은 최초202를 재생한다. 캐시의 QUEUED를 현재 상태로 해석하지 말고 statusUrl을 조회한다. 다른 내용으로 같은 키를 사용하면 409다.

## 수행 상태와 검증 판단

| status / outcome | 의미·A 처리 |
|---|---|
| QUEUED / null | 접수·권한 snapshot·identity 예약 저장 완료 |
| RUNNING / null | worker 하나가 claim. 아직 결과 저장을 보장하지 않음 |
| SUCCEEDED / VALID,WARN | C 판단과 A 저장 시 재검증 통과. 새 version은 **CANDIDATE**로 저장 |
| SUCCEEDED / PROPOSED | C patch 판단을 저장 시 재실행하고 후보·proposal 저장 |
| SUCCEEDED / INVALID | 검증 완료, 부적격. 새 version/proposal 없음 |
| SUCCEEDED / NO_CHANGE_NEEDED | 검증 완료, 변경 불필요. 새 version/proposal 없음 |
| FAILED / null | 실행·출처·권한·저장 오류. 결과 저장 transaction rollback |
| RECOVERY_REQUIRED / null | lease 만료. 외부 호출 상태가 불확실해 자동 재실행하지 않음 |

`result.assessment`는 outcome, `result.issues`는 안전한 검증 code 배열이다.
저장 결과가 있으면 `contractVersionId,resourceHash,policyHash`, 패치는 추가로 `patchProposalId`를 반환한다.
생성 메타데이터와 모델 원문은 status 응답에 싣지 않는다. SUCCEEDED는 APPROVED나 Release PASS가 아니다. 승인은 기존 validate/approve API를 사용한다.

## 저장·메타데이터 계약

A completion transaction에서 호출하는 내부 메서드:

```java
ContractPersistenceService.createReserved(UUID releaseId, JsonNode policy,
    ReviewerContext reviewer, VersionIdentity reservation);
ContractPersistenceService.storePatch(UUID findingId, UUID baseVersionId,
    ProposedPatch candidate, ReviewerContext reviewer, VersionIdentity reservation);
```

RUNNING 예약을 가진 A transaction 안에서 호출한다. C가 별도 transaction/SQL로 저장하지 않는다.
기존 인자 수의 create/storePatch는 수동 후보용으로 유지하며 해당 Release에 생성 예약이 있으면 409다.

`contract_generation_records`는 operation과 실제 저장 version/proposal, metadata JSON 및 canonical hash를 연결하는 불변 기록이다.
JSON은 `generation`(위 Metadata), `source`, `reservedIdentity`, `outcome`을 포함한다.
패치는 같은 JSON을 기존 `patch_proposals.generation_model_meta_json`에 넣어 이전의 `{}`를 대체한다.
INVALID/NO_CHANGE도 생성 기록을 남기지만 version/proposal FK는null이다.
**메타데이터·후보·proposal·작업 성공·감사는 같은 transaction에서 commit한다.**

## 오류·재시도·원본 변경

- 접수 전: 인증/CSRF403, 미지원 body/template400, 출처 없음404, C source 조건 위반422, 활성 Run/동일 Release 생성/queue 용량 초과409, provider 비활성503.
- Worker: C의 `code()`와 A `BusinessException.errorCode()`를 보존한다. 그 외 오류는 `GENERATION_INTERNAL_ERROR`다. 임의 exception message/cause를 공개하지 않는다.
- errorStage는 SOURCE/GENERATION/PERSISTENCE, provider 비활성은 PROVIDER, 권한 만료는 ADMISSION, lease 만료는 WORKER다.
- catalog/fingerprint/analyzedAt, 패치 출처·base hash/state가 달라지면 결과를 저장하지 않고 FAILED. 대표 code는 RELEASE_CHANGED다.
- worker 권한은 접수 시 30분 동안 위임한다. 키/actor/workspace 설정이 바뀌어도 무효화된다. cookie 자체를 worker에 보관하지 않는다.
- A는 자동 재시도하지 않는다. B transport의 기존 retry만 사용한다. MODEL_CALL_FAILURE만으로 timeout/429 또는 안전한 재시도 가능 여부를 추측하지 않는다.
- 새 생성이 필요하면 상태·provider 실행 여부를 확인한 뒤 새 Idempotency-Key로 접수한다. terminal 작업을 SQL로 QUEUED로 돌리지 않는다. 예전 claim의 늦은 결과는 저장할 수 없다.
- HTTP 접수 후 응답 저장 전에 중단되면 기존 idempotency RECOVERY_REQUIRED 절차를 사용한다. 작업의 `admission_id/admission_digest`로 원 예약과 연결된다. 이미 작업이 있는데 미실행으로 판단해 RELEASE하지 않는다.

## 설정·트랜잭션

```text
FINSEC_AI_ENABLED=true
FINSEC_AI_BASE_URL=<기존 B 후보 생성 서비스>
FINSEC_GENERATION_WORKER_ENABLED=true
FINSEC_GENERATION_POLL_MS=1000
FINSEC_GENERATION_LEASE_SECONDS=180
```

기존 FINSEC_CONTRACT_ACCESS_KEY/ACTOR/WORKSPACE도 필요하다. worker 자동 실행에는 finsec.scheduling이 활성화돼 있어야 한다.
AI가 꺼져 있으면 503이고 멱등키를 예약하지 않는다. 202나 모델 결과를 합성하지 않는다. Compose도 해당 변수를 전달한다. 컨테이너 localhost는 host의 AI 서비스가 아니므로 실제 B URL을 설정한다.
lease는 B의 최대 대기/retry 시간과 저장 시간을 합한 것보다 길어야 한다.30..1800초로 설정하며 기본 180초다.

순서: **접수 transaction 종료 → claim/check transaction 종료 → C 생성(호출자 transaction 없음) → A completion transaction**.
모델 대기 중 DB transaction/synchronization을 유지하지 않는다. 여러 프로세스는 DB SKIP LOCKED로 claim을 나누며 프로세스당 worker 하나다. workspace당 최대 20개, Release당 최대 1개의 미완료 생성을 허용한다.

## C/B 후속 연결과 검증 범위

C는 현재 반환 계약을 유지하고, template/판단/metadata 변경 시 adapter 정합성 테스트를 갱신한다. Operation이나 DB 저장을 중복 구현할 필요는 없다.
B 기본 provider의 패치5필드 envelope 지원, 실제 외부 모델 실행, 화면 생성→승인, Replay 실행 당시 비교 원본은 별도 연동 확인 대상이다.
A 테스트는 실제 PostgreSQL·HTTP 접수·실제 C worker/validator를 사용하며 모델 경계 응답은 테스트에서 공급한다. 외부 LLM의 실행 증거는 아니다.

검증 기록: 전체 테스트 2,097개 중 2,096개 통과, 외부 AI 호출 1개 제외. 이후 workspace별 멱등성 및 DB 접수 연결 제약 보완을 포함한 생성 통합 테스트 12개·migration upgrade 1개와 bootJar 재검증 통과.
