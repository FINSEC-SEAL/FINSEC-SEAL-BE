# A Architecture Baseline

## Status

이 문서는 2026-09-01 이후 FINSEC SEAL 구현의 기술 기준이다. 기존 `docs/predev`와 통합 명세의
FastAPI 단일 Backend 또는 MySQL 서술이 이 문서와 충돌하면 이 문서를 우선한다.

## Deployment boundary

```text
React/Vite Console
        |
Spring Boot Core ── PostgreSQL
        |
stateless Python AI service
```

- Spring Boot Core가 Agent, Release, Manifest, Fingerprint, TestRun 상태, ExecutionEvent,
  Evidence, Audit, Decision 저장 및 Attestation projection의 유일한 상태 소유자다.
- Python AI 서비스는 영속 상태를 소유하지 않고 B의 Runtime/Attack 요청을 처리한다.
- PostgreSQL이 canonical state와 evidence source of truth다. MySQL 전용 기능은 사용하지 않는다.

## Pinned versions

| Component | Version | Reason |
|---|---:|---|
| Java | 21 LTS | 장기지원 실행 기준 |
| Spring Boot | 4.1.1 | 신규 greenfield용 현재 stable line |
| Gradle Wrapper | 9.7.1 | 현재 JDK 26에서도 wrapper 실행 가능, Java 21 toolchain 사용 |
| PostgreSQL | 17.11 | 지원 중인 17 계열 최신 보안/버그 수정 minor |
| Node.js | 24 LTS | FE 실행 기준 |
| React | 19.2.x | 안정 minor |
| Vite | 8.x | 안정 major |

Gradle distribution SHA-256은 `gradle-wrapper.properties`에 고정한다. FE의 정확한 patch 버전은
`pnpm-lock.yaml`을 기준으로 재현한다.

## Role boundaries

### A owns

- 공통 Backend 구조, DB migration 및 저장 무결성
- Agent/Release/Manifest/Artifact/Fingerprint
- ExecutionEvent persistence, redaction, sequence/hash chain, SSE/polling
- Audit/Evidence reference storage
- D가 확정한 Decision을 입력으로 한 Attestation JSON/HTML projection
- Release Overview/Fingerprint/Pipeline/Run Status/Attestation UI

### A does not own

- B: Agent Runtime, Tool Dispatcher, 공격/Replay 실행, Sandbox clone/reset
- C: Safety Contract 생성/검증/승인 규칙, Policy Gateway, ALLOW/DENY
- D: Oracle 판단, Finding 판정, Metrics, Release Gate, Decision 계산

A가 B/C/D 객체의 테이블과 repository를 제공하더라도 판단 또는 실행 로직은 구현하지 않는다.

## Shared contracts

공통 Enum, OpenAPI, Trace Event schema, Release/TestRun/Finding 상태, Golden Fixture와 Gate 기준은
4인 공동 소유다. 이 저장소의 초기 값은 `provisional`이며 다른 담당자의 확인 후 호환성을 깨지 않는
migration으로 확정한다.

## Primary references

- Spring Boot system requirements: <https://docs.spring.io/spring-boot/system-requirements.html>
- Gradle Java compatibility: <https://docs.gradle.org/current/userguide/compatibility.html>
- PostgreSQL versioning: <https://www.postgresql.org/support/versioning/>
- Testcontainers PostgreSQL: <https://java.testcontainers.org/modules/databases/postgres/>
