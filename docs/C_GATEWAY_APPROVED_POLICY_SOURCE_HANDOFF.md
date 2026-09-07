# Gateway 승인 정책 출처 연결

2026-09-08, BE `feat/c-gateway-approved-policy-source`, 기준 `dev` `7a78a65`.
초기 생성 worker PR #42와 독립적인 C 기능이다. 기존 정책 인계 문서의
“A 승인 계약 조회 계약 부족” 중 현재 저장 승인본 조회는 이미 A의 공개 메서드로 제공된다.
이 변경은 해당 조회와 실제 Run·caseRun·검증된 카탈로그를 C에서 결합한다.

## 호출과 입력

파일: [GatewayApprovedPolicySourceService.java](../src/main/java/com/finsecseal/policy/GatewayApprovedPolicySourceService.java)

```java
GatewayApprovedPolicySourceService.ApprovedPolicySource load(
    UUID runId, UUID testCaseRunId,
    SafetyContractLifecyclePolicy.ReviewerContext reviewer);
```

Spring bean을 주입받아 호출하는 내부 동기 메서드다. HTTP endpoint, Operation 또는
`PolicyGateway` 구현을 등록하지 않는다. `runId`와 `testCaseRunId`는 실제 저장 ID다.
caller가 인증한 A `ReviewerContext`를 그대로 전달하며, actor 문자열이나 요청 JSON의
인증 플래그로 context를 만들어서는 안 된다. A의 현재 조회는 인증·CSRF 확인과
workspace의 `AI_SECURITY_REVIEWER`/actor/session을 요구한다.

순서는 A `TestRunProjectionService.find(runId)` →
`ContractPersistenceService.approved(run.releaseId(), run.contractVersionId(), reviewer)` →
`TestRunPersistenceService.findCase(testCaseRunId)` →
C `ReleaseToolCatalogContractAdapter.load(releaseId, reviewer.actorId())` → C semantic/canonical 검증이다.
승인 조회의 workspace 권한 확인 이후 case 상세를 읽는다. 원본 projection을 가져오는 A의
조회 API가 인증된 외부 진입점을 대신하지는 않는다.

승인 계약을 적용할 `SEAL_REPLAY`, `HELD_OUT`, `REGRESSION`의 출처를 지원한다.
`BASELINE`은 이 메서드에서 거절한다. 기존 BASELINE 실행과 observe-only 동작은 변경하지 않는다.
Run mode는 Gateway 정책 mode `ENFORCE`와 다른 타입이다. 저장된 Run/case 상태를 그대로
반환하므로 호출 가능 상태·취소 여부의 실행 판단은 후속 실행 경계에서 수행한다.

## 검증과 반환

- 요청 Run/case ID, case→Run 소속, 저장된 정확한 contractVersionId, workspace/Release,
  정책 JSON의 contractId/정수 version을 결합한다.
- A가 저장 무결성과 현재 APPROVED 상태를 확인한다. C는 현재 승인본·Run·카탈로그의
  artifact/release fingerprint 일치와 실제 canonical hash·semantic 검증을 수행한다.
- 더 최근 정책이 승인되면 옛 Run의 계약을 `find()`로 대신 가져오지 않는다.
- 승인으로 Release fingerprint가 바뀌므로 **승인 전 validation proof의 fingerprint**와
  승인 후 현재 fingerprint의 단순 동등성을 요구하지 않는다.

`ApprovedPolicySource`는 private constructor를 가진 불변 결과다.

| accessor | 타입·의미 |
|---|---|
| `runId()`, `testCaseRunId()`, `testCaseId()` | 저장 UUID와 확인된 소속 |
| `runMode()`, `runStatus()`, `caseStatus()` | 실제 `TestRunMode`, `TestRunStatus`, `TestCaseRunStatus` |
| `trialIndex()`, `variantHash()` | 저장된 trial 및 variant 식별 정보 |
| `identity()` | C `VersionIdentity(versionId, workspaceId, releaseId, contractKey, version)` |
| `policyHash()`, `resourceHash()` | 검증한 canonical 정책 hash와 A 저장 resource hash |
| `policy()` | 방어적으로 복사한 Jackson 3 `JsonNode` |
| `catalog()` | C `SourceBoundCatalog`, 실제 Release 결합과 불변 semantic catalog |
| `validation()` | C `ValidationResult`; INVALID이면 결과 반환 불가 |
| `canonicalPolicy()` | C `CanonicalPolicy(canonicalJson, policyHash)` |

Run summary, case result, 승인 review, reviewer/session, raw manifest를 결과에 보관하지 않는다.
이는 **조회 시점의 정책 출처**이며, 전체 server context, preflight PASS, ALLOW 또는
실행 권한이 아니다. 외부에서 임의로 만든 승인 DTO를 받는 API도 아니다.

## 트랜잭션과 실패

실제 Spring proxy가 writable `REPEATABLE_READ` transaction으로 모든 조회를 묶는다.
A의 승인 조회가 획득한 Release 잠금과 기존 접근 감사는 이 transaction에 참여한다.
외부 transaction 없이 호출하면 성공·실패 후 잠금이 해제된다. 호환되는 외부 실제 writable RR에
참여하면 **그 외부 transaction 종료까지** 잠금이 유지된다. 모델·adapter 호출을 같은 경계에 넣지 않는다.

실제 readOnly, READ_COMMITTED, default/unknown 격리의 외부 transaction은 owner 조회 전에 거절한다.
실제 transaction이 없는 `SUPPORTS`는 Spring이 새 writable RR을 만들면 허용한다.
내부 transaction 종료 후 외부 synchronization이 복원되는 것은 잠금 유지와 다르다.

정상 결과는 반환값, 실패는 예외로 전달한다. C `PolicySourceException.code()`는
`INVALID_REQUEST`, `UNSAFE_TRANSACTION`, `UNSUPPORTED_RUN_MODE`, `RUN_BINDING_INVALID`,
`CONTRACT_NOT_APPROVED`, `CASE_RUN_BINDING_INVALID`, `CATALOG_BINDING_INVALID`,
`POLICY_INTEGRITY_FAILURE`, `POLICY_INVALID`, `SOURCE_UNAVAILABLE`이다.
새 C 예외는 고정 메시지·원인 없음·suppressed 비활성이다. A의 기존 `BusinessException`
인증·not-found·무결성 오류 계약은 유지한다. 추가 재시도나 과거 정책 fallback은 없다.

이 실패를 정책 DENY, 공격 차단 성공, ABR 분자로 해석하면 안 된다. HTTP/Run 상태 및
ERROR/INCONCLUSIVE 연결은 소유자의 실행·결과 처리에서 수행한다.

## 구현 범위와 다음 연결

- **C 구현:** 실제 저장 승인·Run/case 소속·카탈로그 결합, 현재 정책 재검증과 불변 출처 반환.
- **A/B 필요:** B의 현재 Gateway 요청에 있는 actorId만으로 A reviewer 권한을 만들 수 없다.
  인증된 실행 주체를 이 내부 진입점에 전달하는 연동이 필요하다.
- **B 필요:** caseRun과 실제 namespace/case/applicant/document/workflow의 서버 관계,
  도구 operation·input schema와 실제 adapter classification/state-delta provenance,
  모델 전달 전 응답 격리 hook. case→Run 소속 확인만으로 이 사실들을 증명하지 않는다.
- **후속 C 작업:** 검증된 출처·서버 사실·요청을 Gateway 평가기에 조립, post-call guard와
  Replay 비교 판단 및 C 화면 연결. A 이벤트 저장·B 실행·D 결과 판정 코드는 각 담당이 유지한다.

이후 연동 요청에도 이 branch/commit/PR, 파일·메서드·입출력, 예외, transaction 전제와
구현된 부분/담당별 남은 연결을 함께 전달한다.

## 검증 증거

하네스 Run `20260907T211205Z-0089936e`에 실행 명령, JUnit 결과와 최종 파일 hash를 보존한다.
신규 unit/실제 PostgreSQL 통합 검증 및 관련 정책·계약 저장 회귀를 실행한다.
C-SC-001/002/003, C-GW-004/007, C-BND-001 중 출처 경계를 검증하며,
TC-CON-001/002/003의 실제 규범 입력도 source에서 거절하는지 확인한다.
저장 trigger의 변조 거절과 mock owner가 반환한 오염 데이터의 C 검출은 구분한다.

TC-GW-010/011/012/013의 실제 runtime 무호출·전달 0, 전체 sandbox 문맥,
외부 LLM, Replay 실행 및 D 지표 완료는 이 source 검증으로 주장하지 않는다.
