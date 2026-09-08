# 저장 Replay 비교 입력 연동

C-REP-001의 `StoredReplayComparabilityService`는 두 CaseRun의 저장 Run·계약·감사·이력을 읽고 출처를 확인한 뒤 기존 비교기에 28개 사실을 전달한다. 현재 공개 조회에 없는 실행 당시 기록은 `ReplayRecordedSource`로 받는다. 해당 기록을 읽는 실제 구현이 아직 없어 production bean과 HTTP 진입점은 등록하지 않았다.

기준은 [FS-07 Replay](predev/06_FUNCTIONAL_SPEC.md#fs-07-replay)와 [TC-REP-001~004](predev/25_TEST_CASE_MATRIX.md)다. 비교 가능성은 정책만 바꾼 실험인지에 대한 C 판단이다. Replay 실행, 공격 성공·차단 판정, 결과 저장과 지표 계산은 각각 해당 역할의 연결이 필요하다.

## C 진입점과 결과

[StoredReplayComparabilityService.java](../src/main/java/com/finsecseal/replay/policy/StoredReplayComparabilityService.java), package `com.finsecseal.replay.policy`:

```java
StoredReplayAssessment compare(
    UUID baselineCaseRunId,
    UUID replayCaseRunId,
    SafetyContractLifecyclePolicy.ReviewerContext reviewer);
```

동기 메서드다. 두 ID는 서로 다른 저장 CaseRun ID다. `reviewer`는 서버가 인증한 기존 문맥(`workspaceId`, `actorId`, `role`, `sessionId`, `authenticated`, `csrfVerified`, `demoMode`)을 사용한다. 요청 JSON으로 승인 여부나 reviewer 인증 사실을 대신 받지 않는다. A `ContractPersistenceService.find(versionId, reviewer)`가 현재 요청자의 접근 권한과 역사적 계약의 무결성을 검사한다. 현재 요청자와 과거 승인자의 actor는 달라도 된다.

반환 타입은 서비스 내부의 immutable `StoredReplayAssessment`다.

| 필드 | 타입·의미 |
|---|---|
| baselineRunId, baselineCaseRunId | UUID, 읽어 확인한 기준 실행 |
| replayRunId, replayCaseRunId | UUID, 읽어 확인한 Replay 실행 |
| replayContractVersionId | UUID, Replay Run에 저장된 역사적 계약 버전 |
| replayPolicyHash | String, A가 검증한 해당 버전의 policy hash |
| comparison | 기존 `ReplayComparabilityResult(boolean comparable, List<Mismatch> mismatches)` |

`Mismatch`는 `MismatchCode code`, `String factPath`만 담는다. `comparable=false`도 정상 비교 결과다. 조회·무결성 실패는 비교 결과로 위장하지 않고 예외로 전달한다. 성공 결과에는 원문 정책, 감사 actor/session, 모델 응답, 전체 controls를 싣지 않는다.

생성자 의존성 순서는 `TestRunProjectionService`, `TestRunPersistenceService`, `ContractPersistenceService`, `FingerprintService`, `ExecutionEventService`, `AuditService`, `ReplayRecordedSource`, `ReplayComparabilityEvaluator`다. 실제 controls reader가 마련되면 이 생성자로 Spring bean을 구성하고 프록시를 통해 호출해야 한다. 현재 테스트 구성만 bean을 만든다.

## 저장 출처와 비교 순서

1. 실제 read-only `REPEATABLE_READ` transaction인지 확인한다. annotation만 믿고 비호환 외부 transaction에 참여하지 않는다.
2. Replay Case→Run→참조 계약을 읽어 A 인증과 version/release/workspace 결합을 확인한다. 이후에만 기준 Case→Run, 감사, event, controls를 읽는다. 기준 실행은 같은 Release여야 하고 계약 참조가 없어야 한다.
3. 두 Run에 저장된 fingerprint를 A의 `releaseFingerprint(artifact, policyHash)` 수식으로 각각 검증한다. 기준은 null policy, Replay는 저장된 계약 버전의 hash를 사용한다. 현재 Release 정책으로 과거 Run을 덮어쓰지 않는다.
4. 아래 규칙으로 계약 승인 기록을 확인한다. 각 Run은 먼저 `history(runId, 0, 1000)`을 읽어 A의 retention 오류를 보존하고, `verifyChain`과 모든 history 페이지의 Run ID·연속 sequence·head/count·cursor·최종 hash를 대조한다.
5. 선택한 Case의 모든 `MODEL_RESPONSE`에서 nonblank `provider`/`model`이 같은 쌍인지 확인한다. 다른 Case로 누락을 채우거나 모델 alias를 resolved model로 대신 쓰지 않는다.
6. 두 controls record의 identity를 확인하고 28개 사실을 조립한다. 조립까지 완료했을 때 비교기를 한 번 호출한다. 그 이전 출처 실패에서는 호출하지 않는다.

| 비교 사실 | 실제 공급 경로 |
|---|---|
| releaseId, artifact fingerprint, fixture version/digest, mode/status, Run 완료 시각, release fingerprint | A `TestRunProjectionService.find(runId)` |
| attackCaseId, variantHash, trialIndex, Case status | A `TestRunPersistenceService.findCase(caseRunId)` |
| modelProvider, modelName | A에 저장된 해당 Case의 검증된 전체 event 이력 |
| contractVersionId, contractHash | Run 참조와 A `contracts.find` 결과; 기준 실행은 null |
| contractApproved | 검증된 version/review와 A `audits.find("CONTRACT_VERSION", versionId, 100)`; 기준은 계약 부재 확인 후 false |
| 나머지 실행 당시 controls와 Case 완료 시각 | 아래 필수 owner reader |

history는 페이지별로 읽지만 A의 `verifyChain` 자체는 전체 event를 메모리에 읽는다. 전체 경로의 일정 메모리 사용량이나 성능 목표 달성을 의미하지 않는다.

## 승인 기록의 해석

검증된 계약의 상태가 CANDIDATE/VALIDATED/REJECTED이면 `contractApproved=false`, SUPERSEDED이면 과거 승인·취소를 추정하지 않고 null이다. null/알 수 없는 상태는 `POLICY_EVIDENCE_INVALID`다.

APPROVED에서는 `review.decision=APPROVED`와 nonblank actor가 필요하다. 조회한 모든 감사 record의 workspace/resource type/version을 확인하고, 승인 record는 actor, `afterDigest=resourceHash`, `metadata.state=APPROVED`, `metadata.policyHash`까지 일치해야 한다. 관찰된 상충·중복 승인이나 malformed 응답은 안전하게 실패한다. 다른 action은 출처 확인 후 승인 증거에서 제외한다.

| 관찰한 승인 기록 | comparator에 전달하는 값 |
|---|---|
| 완전히 결합된 승인 하나, 두 시각 존재, audit.occurredAt ≤ Run.startedAt | true |
| 해당 기록이 100건 내 없거나 시각이 누락됨 | null |
| 관찰한 승인 시각이 Run 시작 이후임 | null |

true는 **저장된 시각 순서에 한정된 증거**다. 감사 시각은 application 시각이며 정확한 DB approved_at, commit 순서, 동기화된 시계, 전체 감사 이력을 증명하지 않는다. 노출되지 않은 clock skew나 긴 transaction을 감지한다고 주장하지 않으며 임의 허용 오차도 만들지 않는다. unknown은 비교기의 승인 증거 부족 결과로 남는다.

## A/B 연결에 필요한 실제 reader

[ReplayRecordedSource.java](../src/main/java/com/finsecseal/replay/policy/ReplayRecordedSource.java):

```java
RecordedCaseControls caseControls(UUID runId, UUID testCaseRunId);

record RecordedCaseControls(
    UUID runId, UUID testCaseRunId, UUID pairGroupId, Long randomSeed,
    Instant caseCompletedAt, UUID namespaceId, String initialStateDigest,
    String resolvedModelId, String modelParametersDigest,
    String runtimeTimeoutMaxStepsDigest, String toolSchemaDigest,
    String ragVersion, String ragConfigDigest) {}
```

동일 과거 Case/trial에 묶인 immutable 저장 기록을 반환해야 한다. record의 run/case ID는 요청과 같아야 한다. nonnull namespace ID는 현재 A/B의 PK/FK 계약에 따라 runId와 같아야 한다. namespace의 실제 존재와 초기 clone 상태는 실행 기록 소유자가 보장해야 한다.

record 내부 누락 값은 null 그대로 반환한다. C는 기본 seed, 현재 시각, `none`, 가짜 digest를 만들지 않는다. null namespace도 누락 사실로 비교기에 전달한다. null record 또는 reader 예외는 조회 실패다. record의 `toString()`은 값을 노출하지 않는다.

| 담당 | 이미 있는 부분 | 필요한 연결과 막히는 C 작업 |
|---|---|---|
| A | 저장 Run/Case, 계약 인증·hash, 승인 감사, history/chain 공개 조회 | 저장 pairGroupId/randomSeed/Case 완료 시각의 공개 read가 부족하다. 이를 포함한 역사적 controls read 계약이 있어야 C가 실데이터로 전체 비교 입력을 완성할 수 있다. |
| B | 실행·namespace·모델 실행 경로 | 실행 당시 resolved model/parameters/runtime/Tool schema/RAG/초기 namespace 상태의 immutable 기록과 조회 연결이 필요하다. 현재 설정이나 현재 sandbox로 과거 기록을 복원하지 않는다. |
| C | A 직접 조회·출처 검증·controls typed port·28개 사실 조립·기존 비교기 호출 | 실제 owner reader 이후 bean/caller 연결과 완전히 저장된 비교 성공 경로 검증을 진행한다. |
| A/B/D 연동 | 기존 저장·실행·판정 경로 | C assessment의 호출·저장 전달, 명세의 HTTP 409 처리, Replay 실행 및 결과/Oracle/지표 연결은 이 서비스의 부수효과로 수행하지 않는다. D가 저장된 comparability 결과를 소비하는 것과 실제 C 계산·저장 연결은 구분한다. |

별도 ApprovalTimestamp API는 요청하지 않는다. 필요한 승인 기록은 기존 A 감사 조회로 읽는다. reader는 원문 Facts, 승인 boolean, comparable/PASS를 전달하는 우회 API가 아니다. 조회 구현과 실제 출처 보장이 제공되기 전에는 테스트용 controls를 production 기본값으로 등록하지 않는다.

## 실패 전달

`StoredReplayComparabilityService.ReplaySourceException.code()`는 다음 enum을 반환한다. 메시지는 `Stored replay source unavailable: <CODE>`로 고정되며 원본 cause/suppressed를 노출하지 않는다.

| 코드 | 의미 |
|---|---|
| INVALID_REQUEST | null/동일 Case ID 또는 reviewer 누락 |
| UNSAFE_TRANSACTION | 실제 read-only RR 경계 미충족 |
| SOURCE_BINDING_INVALID | Run/Case/version/Release/workspace 또는 저장 fingerprint 결합 불일치 |
| POLICY_EVIDENCE_INVALID | 계약 부재·상태·hash·review·승인 감사의 모순/손상 |
| MODEL_HISTORY_INVALID | chain/head/page/cursor/선택 Case 모델 증거 불일치 |
| CONTROL_SOURCE_UNAVAILABLE | controls record 부재 또는 port 호출 실패 |
| CONTROL_BINDING_INVALID | controls run/case 또는 nonnull namespace 결합 불일치 |
| PROCESSING_FAILURE | 그 외 예상하지 못한 처리 실패 |

기존 A read의 `BusinessException`은 인증·not-found·`STREAM_CURSOR_EXPIRED` 등 원래 계약을 보존한다. 외부 controls port가 던진 예외는 `BusinessException`까지 모두 CONTROL_SOURCE_UNAVAILABLE로 감싸 원문을 노출하지 않는다. 호출자는 이 조회 실패를 보안 차단 성공으로 기록해서는 안 된다. C가 HTTP status나 재시도 정책을 새로 지정하지 않는다.

## 검증 범위와 재실행

단위 테스트는 기존 비교기 행렬을 유지하면서 28개 피연산자 전달, nullable 값, 출처 결합, 승인 판정표, 전체 이력·retention, 예외·결과 비노출을 검사한다. 이후 현재 Release가 v2로 바뀌어도 저장 v1을 조회하는 회귀는 단위 source fixture로 검증한다.

PostgreSQL 테스트는 실제 A Agent/Release 생성·분석, 승인 전 BASELINE, 공개 lifecycle 전이, 계약 생성·검증·승인, v1 SEAL_REPLAY와 event/audit 저장을 사용한다. suite/case 준비만 기존 SQL fixture seam을 사용한다. 모델 event는 테스트가 작성한 값이며 실제 B 모델 실행이 아니다. v2를 만들기 위한 가짜 D Decision이나 직접 Release 상태 SQL은 사용하지 않는다.

실제 A 조회와 물리적 read-only RR, 인증 이후 조회 순서, 외부 transaction 참여/거절, synchronization 복원, 성공·실패 후 자원 해제 및 domain·전체 audit·event/head·ReplayLink·Oracle 무변경을 검사한다. `controls unavailable` 경로와 **실제 A 자료 + synthetic controls의 조립 완료 및 비교 결과 반환**을 분리한다. 후자는 완전히 저장된 controls 조회 성공이 아니다. synthetic Case 완료 시각 역시 실제 A 공개 완료 시각으로 취급하지 않는다.

실제 PG 실행에서는 승인 transaction 종료 후 Replay를 시작해도 저장된 승인 시각이 Run 시작 시각보다 늦은 경우를 관찰했다. 앱과 DB는 시각을 기록하는 경로가 다르며 이 관찰만으로 차이의 원인을 단정하지 않는다. 테스트는 실제 시각과 모든 감사 binding을 보존하고 source 호출 전에 독립 기대값을 계산한다. 기록 순서가 맞으면 true·빈 mismatch, 늦으면 false·정확히 `REPLAY_POLICY_BINDING_INVALID`의 `/replay/contractApproved` 한 건을 기대한다. 후자는 조립 실패가 아닌 정상적인 승인 증거 부족 결과다. 시각 변경·sleep·허용 오차로 비교 가능을 만들지 않는다. 단위 테스트의 결정적인 정상·늦은 승인 분기와 실제 PG에서 관찰한 분기도 구분한다.

```sh
./gradlew test --tests 'com.finsecseal.replay.policy.ReplayComparabilityEvaluatorTest' --tests 'com.finsecseal.replay.policy.StoredReplayComparabilityServiceTest' --rerun-tasks --no-build-cache
./gradlew test --tests 'com.finsecseal.replay.policy.StoredReplayComparabilityServiceIntegrationTest' --rerun-tasks --no-build-cache
./gradlew test --rerun-tasks --no-build-cache
```

이 증거는 TC-REP-001/002의 C 출처·비교 판단 범위다. 실제 reader 기반 전체 비교와 HTTP 응답, TC-REP-003/004의 공격 효과 변화·정상 업무 재실행, 응답 격리 및 지표 acceptance는 아직 포함하지 않는다.
