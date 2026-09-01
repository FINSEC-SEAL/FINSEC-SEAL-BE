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
