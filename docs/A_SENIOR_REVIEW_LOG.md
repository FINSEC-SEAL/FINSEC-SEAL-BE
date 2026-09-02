# A Senior Review Log

## Review method

각 게이트는 구현자가 테스트 결과와 고정 commit SHA를 전달하고, 독립 선임 개발자 에이전트가
역할 경계·설계·보안 불변식·테스트 충분성을 검토한다. 미승인 항목은 수정 및 재검증 후 다시 요청한다.

## G0 — Architecture and scope

- Result: conditional approval
- Feedback: Spring Core/PostgreSQL/stateless AI로 기준 통일, A 역할 밖 로직 금지,
  Boot 3.5 OSS 종료와 현 로컬 JDK/Gradle 비호환 해소, PostgreSQL 실검증 필수
- Applied: Boot 4.1.1, Gradle 9.7.1 wrapper, Java 21 toolchain, PostgreSQL 17.11 채택.
  Architecture baseline과 역할 경계를 문서화했다.

## G1 — Common platform and migration, first review

- Result: rejected
- Verified before review: build success, Flyway V1–V4 applied to real PostgreSQL 17.11
- P0 feedback:
  - analyzed Release에 artifact INSERT 또는 manifest/tool/RAG 변경 가능
  - 다른 run/release/workspace evidence 연결 가능
  - digest 형식 및 Evidence/Oracle 불변성 부족
  - immutable Decision row의 invalidation 컬럼을 수정할 수 없는 모델 모순
  - negative DB tests 부재
- P1 feedback:
  - Testcontainers 1.x/2.x 혼합
  - Gradle distribution checksum 누락
  - deprecated HTTP status 사용
  - CORS/배포 secret 기준 보강 필요
- Applied:
  - fingerprint 입력 전체를 DRAFT 이후 DB trigger로 동결
  - aggregate/workspace scope validation trigger 추가
  - `sha256_digest` domain 및 append-only 대상 확대
  - `decision_invalidations` append-only table 분리
  - Testcontainers 2.0.5 좌표로 통일
  - Gradle SHA-256 pin, deprecated API 제거, CORS 계약 보강, local profile 분리
  - 변조/교차 연결/잘못된 digest를 시도하는 PostgreSQL negative tests 추가
- Reverification: `./gradlew clean test --warning-mode all` 성공. 실제 PostgreSQL 17.11에서
  migration 4개와 negative invariant test를 통과했으며 재검토를 요청했다.

## G1 — Second review

- Result: rejected
- Additional P0 feedback:
  - terminal Release fingerprint/hash 변경 보호 및 Decision invalidation 결합 부족
  - RAG, TestCaseRun, ReplayLink, EvidenceReference에 cross-release/run 연결 가능
  - TestRun/TestCaseRun identity snapshot 사후 변경 가능
  - event head 조회가 row lock을 사용하지 않아 concurrent hash-chain fork 가능
  - PatchApproval/ReplayLink mutation 가능
- Applied:
  - fingerprint/hash 변경은 `REMEDIATION→VERIFYING` 또는 terminal→`NEEDS_REVALIDATION`만 허용하고,
    matching APPROVED Contract 및 terminal DecisionInvalidation을 deferred constraint로 확인
  - Release↔RAG workspace, Run↔Case suite, Replay finding/case/release/variant,
    Evidence owner↔source event run/release scope guard 추가
  - TestRun 및 TestCaseRun identity snapshot reparent/mutation/delete 금지
  - `run_event_counters FOR UPDATE`로 append 직렬화, contiguous sequence와 head hash 확인
  - PatchApproval/ReplayLink append-only 및 approval scope guard 추가
  - Sandbox fixture snapshot과 owning TestRun 일치 guard 추가
  - 두 DB connection으로 stale head concurrent append가 block 후 실패하는 테스트 추가
- Reverification: PostgreSQL negative/concurrency tests 성공, fixed commit `6153479`로 재검토

## G1 — Third review

- Result: rejected
- Verified before review: fixed commit만 checkout한 별도 worktree에서 PostgreSQL 17.11 및 전체 Gradle
  test 성공
- Additional P0 feedback:
  - 올바른 이전 hash를 사용한 sequence gap 허용
  - terminal fingerprint 변경 시 과거 Decision invalidation도 인정하고 effective status 강제가 없음
  - Replay 비교 boolean을 실제 Run snapshot과 대조하지 않아 위조 가능
  - 실행에 사용된 TestSuite/TestCase 및 검토 완료 PatchProposal 사후 변경 가능
- Applied:
  - event sequence를 현재 head의 정확한 `+1`로 강제하고 silent-gap negative test 추가
  - 최신 confirmed Decision에 대한 단일 invalidation만 인정하며 terminal 변경 시
    lifecycle/effective status 모두 `NEEDS_REVALIDATION` 강제
  - Replay의 finding source, mode, contract, agent/release fingerprint, fixture/model/variant snapshot을
    DB에서 다시 계산해 전달된 비교 flag와 대조
  - 사용된 TestSuite/TestCase와 검토 완료 PatchProposal에 update/delete guard 추가
  - 과거 invalidation 거부·최신 invalidation 성공·잘못된 effective status 거부를 실제 transaction
    commit 경계에서 검증
- Reverification: `./gradlew clean test --warning-mode all` 성공. 실제 PostgreSQL 17.11에서
  silent-gap, Replay flag 위조, 최신 Decision invalidation 및 commit-boundary 전이를 포함한 전체 검증 후
  fixed commit으로 4차 검토 요청

## G1 — Fourth review

- Result: rejected
- Verified before review: fixed commit `7060144`, PostgreSQL 17.11 및 전체 Gradle test 성공
- Passed from prior review: exact event `+1`, 최신 Decision invalidation/effective status, 실제 Replay
  snapshot flag 대조, used definition/reviewed proposal update 차단
- Additional P0 feedback:
  - 사용된 Suite에 새 TestCase를 추가하거나 미실행 Case를 변경해 suite 구성을 사후 변조 가능
  - 미완료 Run/CaseRun도 Replay evidence로 봉인되고 trial/random seed 동일성 미검증
- Applied:
  - TestSuite를 `BUILDING→READY`로 동결하고 READY/사용된 Suite의 Case insert/update/delete 차단
  - Suite/Case mutation과 TestRun 생성이 동일 Suite row lock으로 직렬화되도록 보강
  - Replay는 양쪽 Run `COMPLETED`, Case terminal/completed, 동일 trial/random seed/non-null pair group을 강제
  - incomplete Replay, random seed mismatch, trial mismatch, used Suite case 추가, 미실행 Case mutation
    PostgreSQL negative test 추가
- P1 applied:
  - DRAFT fingerprint 재계산은 deferred approved-contract guard에서 제외하고 positive test 추가
  - PatchApproval이 Proposal row를 lock하며 APPROVED base/result hash positive/forged test 추가
  - `08_SYSTEM_ARCHITECTURE.md`의 현재 구조를 Spring Core/PostgreSQL 17/stateless AI로 정정
- Reverification: 전체 PostgreSQL 검증 후 fixed commit으로 5차 검토 요청

## G1 — Fifth review

- Result: rejected
- Verified before review: fixed commit `2c4e87c`, PostgreSQL 17.11 및 전체 Gradle test 성공
- Passed from prior review: READY/used Suite 동결, DRAFT recompute, completed Replay와 동일
  trial/seed/pair, APPROVED Patch scope 및 architecture 정정
- Remaining P0 feedback: terminal TestRun/TestCaseRun 결과가 사후 변경 가능하고 terminal Run에도
  ExecutionEvent append 가능
- Applied:
  - active→terminal 전이는 허용하되 terminal TestRun은 status/count/summary/timestamp를 포함한 모든
    update/delete를 거부하고, `COMPLETED`는 completedAt 및 전체 case 완료를 강제
  - terminal TestCaseRun은 outcome/result/timestamp를 포함한 모든 update/delete를 거부
  - terminal Run의 Event append를 거부하고 `RUN_COMPLETED event commit→Run terminal` 순서를 계약화
  - 정상 RUNNING→COMPLETED positive와 terminal Run/Case mutation·late Event negative test 추가
- Reverification: 전체 PostgreSQL 검증 후 fixed commit으로 6차 검토 요청

## G1 — Sixth review

- Result: rejected
- Verified before review: fixed commit `670abed`, PostgreSQL 17.11 및 전체 Gradle test 성공
- Passed from prior review: terminal Run/Case 자체 mutation과 순차 late Event 차단
- Remaining P0 feedback:
  - terminal parent 아래에 새 CaseRun을 추가하거나 active child를 사후 종료해 graph 변경 가능
  - COMPLETED 전이가 caller가 쓴 count만 신뢰하며 실제 child 상태와 미대조
  - Event append와 Run terminal 전이가 같은 lock을 쓰지 않아 commit 순서 경쟁 가능
- Applied:
  - CaseRun INSERT/UPDATE와 Event INSERT가 parent TestRun row를 lock하며 terminal parent면 거부
  - Run terminal 전이가 실제 materialized/terminal child 수와 completed counter를 대조하고,
    COMPLETED는 planned total까지 일치하도록 강제
  - Event append와 terminal 전이를 같은 Run row lock으로 직렬화
  - terminal Run 직접 INSERT 금지, terminal Case 직접 INSERT의 completedAt 강제
  - forged completed counter, terminal parent child 추가, direct terminal insert negative 및
    FAILED/CANCELLED 정상 전이 positive test 추가
  - 두 connection으로 Event commit이 terminal transition보다 반드시 먼저 완료되는지 검증
- P1 applied:
  - TestRun 생성↔Suite mutation, Approval insert↔Proposal mutation을 두 connection race로 검증
  - Decision insert가 Release parent row를 lock하도록 해 fingerprint 전이와 직렬화하고 race test 추가
- Reverification: 전체 PostgreSQL 검증 후 fixed commit으로 7차 검토 요청

## G2 — Agent/Release/Manifest/Fingerprint implementation review

- Scope: Role A의 Agent CRUD/archive, strict Manifest validation, artifact encryption/catalog storage,
  JCS/NFC fingerprint/diff/integrity, latest Decision invalidation evidence, durable API idempotency
- Boundary check: Runtime/Attack 실행, Contract/Policy 판단, Oracle/Finding/Metric/Decision 계산은 미구현
- Security checks:
  - prompt plaintext가 Release manifest/DB JSON에 남지 않고 AES-256-GCM artifact로만 저장
  - Manifest remote schema reference, regex lookaround, unknown field, arbitrary adapter, external egress,
    RAG digest 누락 및 spoofed SafetyContractRef 거부
  - Tool/RAG name-version catalog drift 거부와 DRAFT 이후 DB immutability 결합
  - idempotency reservation을 mutation보다 먼저 저장해 response 저장 실패 시 재실행을 fail-closed 처리
- Reverification: 실제 PostgreSQL 17.11에서 Release lifecycle/catalog/encryption/manual invalidation 및
  real HTTP idempotent replay/body conflict/missing key/processing reservation 테스트 포함
  `./gradlew clean test --warning-mode all` 성공
- Review status: fixed commit을 생성해 선임 G2 리뷰 요청 예정

## G1 — Seventh review

- Result: rejected
- Verified before review: fixed commit `16bb82f`, PostgreSQL 17.11 및 전체 Gradle test 성공
- Passed from prior review: terminal parent 아래 CaseRun/Event 차단, 실제 child/counter 대조,
  direct terminal Run 차단, Event→terminal 및 Suite/Approval/Decision row-lock 직렬화
- Remaining P0 feedback:
  - `total_cases`를 terminal 전이와 동시에 축소하면 planned coverage를 거짓 완료할 수 있음
  - Oracle/Finding INSERT가 parent Run을 lock하거나 terminal 상태를 확인하지 않아 종료 뒤 증거를
    추가하거나 terminal 전이와 경쟁할 수 있음
- Applied:
  - `total_cases`를 Run identity snapshot에 포함해 생성 이후 변경을 전면 차단
  - terminal 시 `operational_error_count`를 실제 `ERROR` CaseRun 수와 대조
  - Oracle INSERT와 새 Finding INSERT가 source TestRun row를 `FOR UPDATE`하고 terminal이면 거부
  - 새 Finding의 `first_seen_run_id`가 source Oracle의 Run과 동일하도록 강제
  - planned-total downshift, forged operational error count, late Oracle/Finding negative test 추가
  - Oracle/Finding commit과 terminal 전이 경쟁은 두 connection과 PostgreSQL `lock_timeout`을 사용해
    실제 row-lock 대기(`55P03`)와 증거 commit 후 정상 terminal 전이를 검증
- Reverification: 실제 PostgreSQL 17.11 대상 `MigrationIntegrationTest` 성공. 전체 test 및 fixed commit
  생성 후 8차 검토 요청 예정

## G1 — Eighth review

- Result: rejected
- Verified before review: fixed commit `6ed31fb`, 실제 PostgreSQL 17.11에서 19 tests 성공
- Passed from prior review: planned total/operational error count 봉인, Oracle/Finding terminal 차단 및
  `lock_timeout` 기반 concurrency 검증
- Remaining P0 feedback: Finding row 삭제와 `source_oracle_result_id`/`first_seen_run_id` 재연결이
  가능해 unresolved gate evidence와 provenance를 사후 재작성할 수 있음
- Applied:
  - Finding DELETE 전면 차단
  - `release_id`, source Oracle, first-seen Run, category, severity, violated invariant를 provenance로 고정
  - source Oracle Run과 first-seen Run 일치를 INSERT/UPDATE 모두에 강제
  - delete, first-seen/source reparent, severity mutation, 잘못된 신규 first-seen negative test 추가
  - 정상 `OPEN→TRIAGED`, root cause 및 same-release latest-seen 갱신 positive test 추가
- Reverification: PostgreSQL targeted/full test와 fixed commit 생성 후 9차 검토 요청 예정

## G1 — Ninth review

- Result: approved
- Reviewed fixed commit: `86177e60294d347292bbae4df4a663908fb1cf1d`
- Independent verification: 선임의 격리 detached worktree와 PostgreSQL `17.11-alpine`에서 전체 19 tests,
  실패 0건
- Confirmed:
  - Finding delete와 provenance reparent/severity mutation 차단
  - 정상 `OPEN→TRIAGED`, root-cause 및 same-release latest-seen 갱신 허용
  - G1 범위의 P0/P1 잔여 항목 없음
- Gate: G1 PASS

## G2 — First review

- Result: rejected
- Reviewed fixed commit: `c381ef0c7564ace74a3b7122c11171215918c67c`
- Independent verification: 선임의 clean detached worktree, PostgreSQL `17.11-alpine`, 19 tests 전부 통과,
  `git diff --check` 통과, Role B/C/D 로직 침범 없음
- P0 feedback:
  - Tool name/version과 operation/adapter/side-effect/trust/classification의 서버 고정 조합 검증이 없어
    정상 Tool 이름에 다른 adapter를 연결할 수 있음
  - analyze/fingerprint가 저장된 derived artifact와 Tool/RAG catalog/link 전체를 canonical manifest와
    재대조하지 않음
  - idempotency filter가 advisory-lock 전용 connection을 controller 완료까지 점유해 작은 pool에서
    connection 고갈 가능
  - analyze와 DRAFT child/catalog mutation이 동일 parent lock으로 완전히 직렬화되지 않음
- P1/P2 feedback:
  - Agent archive/create/update 경쟁에 row lock 또는 optimistic version 필요
  - 불확정 PROCESSING 및 retryable 500 replay의 복구 규칙, request semantic digest 보강 필요
  - RAG/human-boundary canonical sort tie-breaker와 validator type/meaning 검증 보강 필요
  - mutable JsonNode setter 방어 복사, integrity 오류의 정확한 API 분류, 실제 actor 증적 필요
- Gate: G2 FAIL. P0 수정 및 concurrency/negative test 추가 후 재검토 요청

## G2 — First review feedback applied

- Tool contract:
  - 서버 고정 normal Tool 5종에 대해 name/version/operation/adapter/side-effect/trust/risk/
    classification 전체 조합을 정확히 대조
  - `LOAN_DECISION_UPDATE`, `EXTERNAL_HTTP` 등 attack-only Tool의 Release manifest 선언 거부
- Derived integrity:
  - canonical manifest에서 artifact 기대 집합을 재생성해 개수/content/digest/sensitivity/canonicalization을 대조
  - Tool definition/link의 ordinal/enabled/schema/description/metadata/digest와 RAG source/link/config/digest를
    analyze/validate/fingerprint/diff 전에 전부 대조
- Idempotency:
  - 요청 전체 동안 advisory-lock 전용 connection을 점유하던 구조 제거
  - unique row `INSERT ... ON CONFLICT DO NOTHING` 기반 atomic reservation으로 변경
  - body뿐 아니라 Content-Type/If-Match를 request digest에 포함
  - 만료 PROCESSING 및 5xx는 자동 재실행/replay하지 않고 operator recovery가 필요한 fail-closed 상태로 유지
- Concurrency:
  - Release child/Tool/RAG definition mutation이 Release parent row를 lock하도록 DB function 보강
  - Agent update/archive/Release create가 동일 Agent row lock을 사용하고 DB도 archived Agent Release insert 거부
  - child-first/analyze-first 및 archive-first/create-wait 양방향 real PostgreSQL race test 추가
- P1/P2:
  - RAG sourceId+version, human boundary, provider host 배열의 canonical tie-breaker 보강
  - non-string prompt digest, configured provider/host, human boundary 의미 검증 보강
  - entity 입력 JsonNode defensive copy 및 manual invalidation 실제 actor 기록
- Regression found and fixed:
  - 동시 Event append에서 한 SQL의 row lock+lateral head 조회가 stale snapshot을 반환할 수 있음을 전체
    테스트가 탐지
  - Run row lock을 먼저 획득한 뒤 별도 SQL의 새 snapshot으로 event head를 조회하도록 변경하고
    동시 append 검증을 10회 반복
- Reverification: `git diff --check` 성공, PostgreSQL `17.11-alpine` 기반
  `./gradlew clean test --warning-mode all --rerun-tasks` 전체 45 tests, 실패 0건
- Gate: fixed commit 생성 후 G2 재검토 요청

## G2 — Second review

- Result: rejected
- Reviewed fixed commit: `a23d17ad57695990dbc5918222f5cf12f9c33faf`
- Independent verification: 선임의 clean detached worktree와 실제 PostgreSQL `17.11-alpine`에서
  `git diff --check` 및 전체 45 tests 성공
- Confirmed closed:
  - 이전 P0 4건(Tool 고정 registry, derived integrity, idempotency connection 고갈, analyze TOCTOU)
  - Agent archive/create race, mutable JSON defensive copy, B/C/D 역할 경계
- Remaining P1 feedback:
  - `temperature`/`topP` 문자열 숫자와 `allowedStages` 비문자·중복을 strict manifest가 수용
  - system prompt 복호화 뒤 integrity failure가 발생하면 동일 transaction의 접근 audit도 rollback
  - 만료 `PROCESSING` idempotency reservation에 실제 operator recovery 계약 부재
- P2 feedback:
  - Tool/RAG definition-first 및 analyze-first actual concurrency test 추가 권고
  - JSON object field name NFC 정규화 누락
  - `ReleaseArtifactEntity` constructor의 JsonNode defensive copy 권고
- Gate: G2 FAIL. P1 수정 후 재검토 필요

## G2 — Second review feedback applied

- Strict manifest:
  - `temperature`/`topP`에 실제 JSON number 타입을 요구하고 문자열 숫자를 `TYPE` 오류로 거부
  - `allowedStages` 원소의 non-blank string 타입과 중복 금지를 index별 오류로 검증
- Rollback-safe prompt access audit:
  - 복호화 접근 audit를 현재 transaction에 기록하되, 이미 commit된 Release에 대한 호출이 rollback되면
    transaction completion callback에서 독립 transaction으로 동일 접근 증적을 복원
  - derived artifact tamper로 integrity 검증이 실패한 실제 rollback 경로에서 audit 보존 통합 테스트 추가
- Operator idempotency recovery:
  - 별도 32-byte 이상 운영자 키와 `operator:` actor를 모두 요구
  - 만료된 `PROCESSING`만 exact actor/method/path/key/requestDigest로 row-lock 후 복구
  - 미처리 확인 시 `RELEASE`, 이미 처리 확인 시 검증된 status/body/Location/trace를 등록하는 `COMPLETE`
  - pending 조회 API, 불변 recovery row, scope-checked audit, DB identity/transition/delete guard 추가
  - 잘못된 운영자 키, RELEASE 후 원 요청 실행, COMPLETE 후 정확한 응답 replay를 real HTTP로 검증
- P2 also applied:
  - Tool/RAG 각각 definition-first 및 analyze-first 양방향 two-connection concurrency test 추가
  - JSON value와 object field name 모두 NFC/LF 정규화하고 normalization collision 거부
  - `ReleaseArtifactEntity` constructor defensive copy 추가
- Additional Attestation hardening during G4:
  - 이미 tokenized synthetic ID의 재-HMAC 방지
  - Decision 무효화 후 현재 Release fingerprint/contract가 달라져도 당시 immutable snapshot으로
    stale Attestation을 생성하는 회귀 테스트 추가
- Reverification: `git diff --check` 성공. 실제 PostgreSQL `17.11-alpine` 대상
  `./gradlew clean test --warning-mode all --rerun-tasks` 전체 55 tests, 실패/오류/skip 0건.
  fixed commit 후 동일 선임에게 G2 third review 요청 예정

## G2 — Third review

- Result: rejected
- Reviewed fixed commit: `f397782d3343cc0b3e05039164690b475b8ad352`
- Independent verification: 선임의 clean detached worktree와 PostgreSQL `17.11-alpine`에서
  전체 55 tests 통과
- P0 feedback:
  - prompt rollback audit의 `REQUIRES_NEW` 접근이 outer transaction 커넥션 반납 전에 다른
    커넥션을 요구해 작은 pool에서 starvation/deadlock 가능
  - Attestation은 DB에서 부분 projection만 비교하고 기존 row의 서비스 expected rebuild를
    생략해 self-consistent forged document/hash를 허용 가능
  - recovery row 위조로 활성 reservation을 삭제할 수 있는 DB transition 결함
- P1 feedback:
  - TTL 경계에서 활성 원 요청과 operator recovery가 경합할 수 있어 실행 lease 필요
  - latest Decision/Invalidation과 Attestation 생성 TOCTOU
  - Decision snapshot evidence completeness/DB closure 검증 부족
  - invalidation된 과거 Decision이 현재 lifecycle `VERIFYING` 등일 때 historical Attestation 생성 실패
- P2 feedback:
  - concurrent Attestation/invalidation/latest Decision test 부족
  - recovery response digest가 body만 복인하고 HTTP metadata를 봉인하지 않음
  - 잘못된 복구 credential 403이 명령의 idempotency key를 오염시킬 수 있음
  - NFC field-name collision이 정의된 manifest 오류 대신 500으로 노출
- Gate: G2 FAIL

## G2 — Third review feedback applied

- Prompt audit:
  - outer transaction에서 이벤트만 발행하고 `AFTER_ROLLBACK` 후 bounded async executor에서
    새 transaction으로 audit을 복원하도록 커넥션 순서 분리
  - Hikari pool 2개로 동시 rollback 2건을 발생시켜 요청 종료와 audit 보존 모두 검증
- Attestation:
  - Release row lock 후 latest Decision/invalidation/snapshot을 읽어 Decision 생성과 직렬화
  - 기존 row도 immutable Decision snapshot에서 expected JSON/hash/HTML을 매번 재생성해 exact 비교
  - DB trigger도 latest Decision과 snapshot의 모든 projection field, Decision/reviewer/disclaimer를 재대조
  - TestSuite/Run/Finding의 release/workspace closure, result/metric fraction·digest·source,
    PASS 근거, patch/rule trace의 구조를 검증
  - 동시 생성/latest Decision/invalidation, forged metric, forged HTML, historical lifecycle 회귀 테스트 추가
- Idempotency recovery:
  - application instance UUID lease/heartbeat와 owner를 reservation에 기록
  - 5xx/예외 종료 또는 `TTL 만료 + owner lease stale`일 때만
    `RECOVERY_REQUIRED`로 전환하는 DB 상태 머신 도입
  - exact recovery evidence INSERT를 원 row COMPLETE/DELETE보다 먼저 하고 DB trigger로 항목 전체 대조
  - 인증 pre-filter를 idempotency filter 전에 배치해 잘못된 credential이 명령 키를 점유하지 못하게 함
  - status/contentType/Location/traceId/bodyDigest canonical envelope를 response digest로 사용
  - 활성 owner, stale owner, forged recovery, wrong-credential reuse, exact replay를 real HTTP/DB로 검증
- Manifest:
  - NFC object-field collision을 `MANIFEST_INVALID`로 정규 매핑하고 통합 테스트 추가
- Reverification: `git diff --check` 성공. 실제 PostgreSQL `17.11-alpine`에서
  `./gradlew clean test --warning-mode all --rerun-tasks` 전체 64 tests,
  실패/오류/skip 0건. fixed commit 생성 후 동일 선임에게 fourth review 요청 예정

## G2 — Fourth review

- Result: rejected
- Reviewed fixed commit: `981294ca012efba72f34b042d700c9532cd054d4`
- Independent verification: clean fixed commit, `git diff --check`, PostgreSQL `17.11-alpine`
  전체 64 tests는 모두 통과
- P0 feedback and reproduction:
  - V9 trigger가 주체/lease 증명 없이 모든 `PROCESSING → RECOVERY_REQUIRED` UPDATE를 허용
  - active row에 `execution_finished_at`/`recovery_reason`을 직접 채운 뒤 exact RELEASE recovery를
    INSERT하면 활성 reservation DELETE가 가능한 2단계 우회
- Additional review observations:
  - rollback audit의 in-memory async queue는 process 종료 시 접근 증적을 잃을 수 있음
  - historical Decision snapshot의 Finding status를 현재 mutable Finding status와 재대조하면 과거
    Attestation이 사후 상태 변경에 결합될 수 있음
  - direct invalidation INSERT도 Attestation과 같은 Release parent lock에 직렬화할 필요
- Gate: G2 FAIL

## G2 — Fourth review feedback applied

- Idempotency transition proof:
  - 인스턴스 메모리에만 있는 256-bit random secret과 DB의 SHA-256 hash를 단일 SQL
    statement 안에서 대조해 owner만 `COMPLETED`/5xx·예외 `RECOVERY_REQUIRED` 전환 가능
  - transition secret hash와 instance identity를 DB trigger로 불변화
  - owner lease expiry와 reservation TTL이 모두 만료된 `OWNER_LEASE_EXPIRED`만 proof 없이 허용
  - FORGED 사유, 정상 사유 위조, 위조 proof, secret hash 교체를 모두 DB negative test로 차단
- Prompt audit durability:
  - in-memory async queue를 제거하고 메인 transaction pool과 분리된 전용 2-connection pool에서
    `AFTER_ROLLBACK` audit를 동기 commit
  - 메인 Hikari pool 2개를 모두 점유한 동시 rollback 2건이 교착 없이 완료되고
    반환 시점에 audit가 이미 저장됐음을 검증
- Historical Attestation:
  - Finding ID/release/severity/source Oracle evidence digest는 immutable provenance로 대조하되,
    Decision 후 변경 가능한 현재 Finding status는 historical snapshot에 재투영하지 않음
  - DecisionInvalidation INSERT에도 Release parent `FOR UPDATE`를 추가해 Attestation/latest
    Decision/invalidation을 하나의 직렬화 지점으로 통일
  - direct invalidation이 이미 잡힌 Release lock에 대기한 뒤 stale Attestation이 되는
    two-connection concurrency test 추가
- Reverification: `git diff --check` 성공. PostgreSQL `17.11-alpine`에서
  `./gradlew clean test --warning-mode all --rerun-tasks` 전체 65 tests,
  실패/오류/skip 0건. fixed commit 후 fifth review 요청 예정

## G2 — Fifth review

- Result: rejected during independent fixed-commit review
- Reviewed fixed commit: `089cfcdc006b5baa637051090835f1909828dcc4`
- Independent verification: PostgreSQL `17.11-alpine` 전체 65 tests 통과,
  transition proof가 정상 HTTP completion과 forged secret/hash 변경을 의도대로 분리함
- Remaining feedback:
  - application lease의 `lease_expires_at`/`stopped_at`은 owner proof 없이 변경 가능해
    expired reservation을 `OWNER_LEASE_EXPIRED`로 위조할 수 있음
  - stale reconciler가 lease row lock 없이 heartbeat snapshot을 읽으면 활성 owner의 동시
    heartbeat를 놓치고 recovery-ready로 전환할 수 있음
  - `RollbackAuditWriter.java` EOF blank line으로 fixed commit 대상 `git diff --check` 실패
- Gate: G2 FAIL

## G2 — Fifth review feedback applied

- Lease mutation:
  - heartbeat/expiry/stop 변경도 인스턴스 transition secret proof가 있는 단일 SQL에서만 허용
  - heartbeat와 lease expiry의 단조 증가, 이미 stopped된 lease의 추가 변경 거부
  - proof 없는 expiry 축소/stopped 위조를 PostgreSQL negative test로 차단
- Heartbeat/reconciler serialization:
  - own heartbeat를 독립 statement로 먼저 commit한 뒤 stale reconciliation 실행
  - stale 후보의 reservation과 lease를 `FOR UPDATE OF record, lease SKIP LOCKED`로 선점해
    진행 중인 heartbeat lease는 건너뛰
  - two-connection test에서 owner heartbeat가 lease lock을 잡은 동안 reconciler가 종료되더라도
    reservation은 `PROCESSING`을 유지하고, heartbeat commit 후 재조회해도 유지됨을 검증
- Hygiene: `RollbackAuditWriter.java` EOF 공백 제거, `git diff --check` 성공
- Reverification: PostgreSQL `17.11-alpine` 전체 66 tests,
  실패/오류/skip 0건. fixed commit 후 sixth review 요청 예정

## G2 — Sixth review

- Result: rejected
- Reviewed fixed commit: `2b6de5df190aa28fa04975232ac6ba693aaace08`
- Independent verification: lease owner proof/monotonic time, heartbeat ↔ reconciler lock 순서는 일관되고
  PostgreSQL 17.11 전체 66 tests가 통과함
- Remaining P1 feedback:
  - 이미 배포됐을 수 있는 Flyway `V9__idempotency_execution_lease.sql`을 수정해,
    기존 V9 DB가 startup validation checksum mismatch로 중단될 수 있음
  - clean-database 테스트만으로는 이 upgrade 경로가 검증되지 않음
- Gate: G2 FAIL

## G2 — Sixth review feedback applied

- `V9` 파일을 부모 commit `089cfcdc` 바이트와 동일하게 복원하고
  SHA-256 `09e79ccfb30a6a68fdc44be96700c10692cb17e2cba3f27d1a7645f41e14fc05`를 테스트에 고정
- lease owner proof/monotonic update 함수 교체를 새
  `V10__application_instance_lease_owner_guard.sql`로 이동
- 실제 PostgreSQL 17.11에 V1–V9만 우선 적용한 뒤 현재 Flyway로 V10 1건을
  upgrade하고 checksum validation과 proof 없는 lease update 거부를 확인하는 통합 테스트 추가
- `MigrationIntegrationTest`의 clean-database migration expectation을 V1–V10으로 갱신
- Reverification: targeted upgrade test PASS; `./gradlew clean test --warning-mode all --rerun-tasks`
  전체 67 tests, 실패/오류/skip 0건; `git diff --check` PASS; V9 바이트 일치 PASS
- Gate: fixed commit 생성 후 seventh review 요청

## G2 — Seventh review

- Result: approved
- Reviewed fixed commit: `793dcbbd97ef8a057e280f9f1c1e04d3bcab0a58`
- Independent verification:
  - `V9`이 `089cfcdc` 기준과 byte-for-byte 동일하고 SHA-256
    `09e79ccfb30a6a68fdc44be96700c10692cb17e2cba3f27d1a7645f41e14fc05` 일치
  - owner proof/monotonic-time guard가 새 `V10` migration으로 적용됨
  - upgrade test가 빈 PostgreSQL DB에 V1–V9 9건을 우선 적용하고 V10 한 건만
    추가 적용한 뒤 Flyway history와 proof 없는 lease update의 SQLSTATE `23514`를 검증
  - targeted upgrade test PASS, 전체 67 tests / failure 0 / error 0
- Remaining findings: none
- Gate: G2 PASS
