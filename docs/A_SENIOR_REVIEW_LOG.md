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
- Reverification: PostgreSQL negative/concurrency tests 성공 후 fix commit으로 재검토 예정
