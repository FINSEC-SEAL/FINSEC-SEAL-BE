# 승인 정책 의미 검증 캐시

명세 `docs/predev/16_POLICY_GATEWAY_SPEC.md`의 policy/context cache 요구 중,
C `GatewayApprovedPolicySourceService`의 의미 검증 결과 재사용과 로컬 무효화를 구현한다.
기존 [승인 정책 출처 계약](C_GATEWAY_APPROVED_POLICY_SOURCE_HANDOFF.md)의 조회·반환·오류는 유지한다.

## C 진입점

파일: [GatewayApprovedPolicySourceService.java](../src/main/java/com/finsecseal/policy/GatewayApprovedPolicySourceService.java)

| 메서드 | 입력 | 정상 결과와 실패 전달 |
|---|---|---|
| `load(UUID runId, UUID testCaseRunId, ReviewerContext reviewer)` | 실제 저장 Run·CaseRun ID와 인증된 A reviewer context | 매번 새 `ApprovedPolicySource`를 반환한다. 기존 `PolicySourceException.code()`와 A `BusinessException` 계약을 유지한다. |
| `invalidateRelease(UUID releaseId)` | 무효화할 실제 Release ID | 해당 Release의 저장 캐시를 비우는 동기 `void` 메서드다. `null`은 `PolicySourceException`의 `INVALID_REQUEST`로 거절한다. |

두 메서드는 같은 Spring service bean에서 사용한다. 기존 public 6인자 생성자를 유지한다.
추가 HTTP endpoint, Operation, 정책 승인 또는 실행 권한을 만들지 않는다.

## 재사용해도 유지되는 현재 상태 확인

`load`는 매 호출 Run → A의 현재 권한·승인 조회 → CaseRun → 검증된 Release 카탈로그와
Tool binding 확인을 수행한다. 승인 조회의 Release 잠금과 접근 감사도 유지한다.
Run·Case 상태와 카탈로그는 현재 조회값으로 새 source에 투영한다. 적중한 검증 결과가
이전 source나 reviewer 권한, ALLOW 판단, 실행 가능 상태를 대신하지 않는다.

재사용 대상은 불변 `ValidationResult`의 `VALID` 또는 `WARN` 결과다.
캐시가 없으면 기존대로 의미 검증을 먼저 수행하여 잘못된 정책을 `POLICY_INVALID`로 거절하고,
그 후 현재 복사한 정책의 canonical hash를 확인한다. 적중 후보가 있더라도 현재 정책의
canonicalization과 실제 hash 확인을 통과해야 그 결과를 재사용한다.
실패·INVALID 결과나 과거 source로의 fallback은 없다.

키는 workspace·Release·contract version ID, policy/resource hash, artifact/release fingerprint,
manifest schema version·server Tool catalog hash, 정규화하지 않은 현재 정책 JSON의 SHA-256,
정확한 불변 semantic catalog를 포함한다. Unicode NFC나 줄바꿈 정규화 후 hash가 같더라도
필드 이름의 실제 의미가 다르면 같은 검증 결과를 사용하지 않는다. raw 정책은 캐시에 보관하지 않는다.

## 수명·트랜잭션·무효화

`load`의 실제 writable `REPEATABLE_READ` 전제는 그대로다. 성공한 계산도 실제 트랜잭션의
`afterCommit`에서만 게시한다. 외부 트랜잭션이 있으면 그 commit까지 대기하며 rollback은
게시하지 않는다. synchronization이 없으면 캐시 저장을 생략하고 기존 source 검증을 수행한다.
이 동작은 실제 transaction이 없는 호출을 허용한다는 의미가 아니다.

TTL은 실제 commit 후 캐시에 게시한 시점부터 단조 시계 기준 5분이며 적중으로 연장하지 않는다.
정책 검증 결과의 이 TTL은 로컬 구현 선택이다. 명세의 Run context TTL 5분을 구현했다는
의미는 아니며, Run context는 이 캐시에 포함되지 않는다.

기본 저장 entry와 commit 대기 예약의 상한은 각각 128개다. 하나의 키·catalog·검증 결과를
합쳐 문자열 1,024개와 총 길이 32,768 이내(`String.length()` 기준)만 저장한다. 키의 hash·manifest version 문자열,
Tool·필드 이름, issue의 pointer·code·message를 세며 고정 크기 UUID·enum은 제외한다.
한도 초과나 키 직렬화 실패는 캐시만 생략하며
유효한 source에 새로운 거절 사유를 추가하지 않는다. 대기 예약은 commit·rollback 모두의
`afterCompletion`에서 해제한다. 캐시 잠금 안에서 owner 조회·직렬화·의미 검증을 수행하지 않는다.

무효화 세대는 첫 owner 조회 전에 포착한다. `invalidateRelease`는 해당 Release의 저장 entry를
삭제하고 세대를 변경하여, 그 전에 조회 중이거나 commit을 기다리던 결과가 다시 게시되지 않게 한다.
보수적인 전역 세대 변경은 다른 Release의 이전 대기 결과도 게시하지 않게 할 수 있다.
다른 Release의 이미 저장된 entry는 유지한다. 캐시는 프로세스별 메모리 상태다.

## 담당별 남은 연결

- A의 승인·Release 무효화·감사 API는 이미 존재한다. 다만 commit된 승인/무효화를 알리는
  이벤트 타입, `releaseId`, 전달·재전송 계약과 C 구독 연결은 아직 연결되지 않았다.
  A가 제공하는 확정 이벤트를 C 소비자가 받아 같은 bean의 `invalidateRelease(releaseId)`를
  호출해야 자동 무효화가 완성된다. 여러 서버 인스턴스에 대한 전달도 필요하다.
- B의 실행 문맥은 변경되지 않는다. 전체 Run context 캐시를 연결하려면 불변 문맥의 수명과
  호출별 invocation·operation·ACTIVE 상태 관측을 구분하는 실제 공급 계약이 필요하다.
- C의 직접 eviction 검증은 A 이벤트 발행·전달·구독의 종단 검증이 아니다.
  이 변경은 owner DB 조회 감소, 전체 Gateway 지연 목표, 실제 공격 차단·응답 격리나 D 지표를
  검증한 것으로 취급하지 않는다.

## 검증 범위

기존 source 단위 테스트와 PostgreSQL 19개 사례를 유지한다. 단위 검증은 정확한 키 분리,
Unicode 의미 차이, 현재 권한·binding·hash 재검증, 불변 결과, 오류 순서, TTL 경계·비연장,
지연 commit, 용량·대기 예약·메타데이터 상한과 무효화 경합을 다룬다.
실제 PostgreSQL에서는 commit 후 적중과 외부 rollback 후 미게시 두 사례를 추가하고,
캐시를 채운 뒤 다른 workspace와 교체된 승인이 여전히 거절되는지 확인한다.
의미 검증 재사용과 별개로 매 호출의 owner 조회·C hash 확인·접근 감사·잠금 해제·데이터 불변을 검증한다.
기존 REMEDIATION 직접 SQL은 테스트 준비 수단이며 실제 A lifecycle 수용 증거로 확대하지 않는다.

실행 명령과 최종 파일 hash, 개별 JUnit 결과는 하네스 Run
`20260908T154644Z-202253d2`에 기록한다. 필수 source 두 suite와 전체 회귀 검증은
`./gradlew test --rerun-tasks --no-build-cache`로 실행하며, source 두 suite를 지정한 실행에서는
신규 캐시 사례와 PostgreSQL 총 21건의 실제 실행·무생략 여부를 별도로 확인한다.
