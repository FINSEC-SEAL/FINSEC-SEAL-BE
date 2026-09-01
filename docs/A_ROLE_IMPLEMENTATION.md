# A Role Implementation

## Repository responsibility

이 저장소에서 A는 Platform / Data / Evidence 기반만 구현한다. Runtime/Policy/Oracle/Gate의
실행·판정 로직은 구현하지 않는다.

## Implemented

### G1 — Common platform and persistence

- Java 21 / Spring Boot 4.1.1 / Gradle 9.7.1 project
- PostgreSQL 17.11 local/Testcontainers environment
- 공통 response, RFC 9457 ProblemDetail, validation, trace ID, CORS
- UUIDv7 ID foundation과 공통 상태 Enum
- Release, execution, evidence, audit, decision, sandbox 저장 schema
- `sha256_digest` DB domain
- Release fingerprint input immutability guards
- cross-workspace/run/release evidence scope guards
- ExecutionEvent/Oracle/Evidence/Audit/Decision/Attestation append-only guards
- 별도 append-only `decision_invalidations`

## Run and verify

```bash
./gradlew clean test --warning-mode all
```

이 테스트는 실제 `postgres:17.11-alpine`을 시작하므로 Docker가 필요하다. H2로 대체하지 않는다.

```bash
cp .env.example .env
# FINSEC_DATA_ENCRYPTION_KEY_BASE64에 `openssl rand -base64 32` 결과 입력
docker compose up --build
```

## Integration contracts for B/C/D

- 공통 Enum과 DB schema는 공동 계약 전까지 provisional이다.
- B는 A가 제공할 TestRun 상태/ExecutionEvent append API를 사용하고 실행 엔진은 B가 소유한다.
- C는 Safety Contract 저장 기반을 사용하고 policy/approval 판단은 C가 소유한다.
- D는 Oracle/Finding/Decision 저장 기반을 사용하고 판단 계산은 D가 소유한다.
- Attestation은 D의 확정 Decision이 없으면 생성할 수 없다.

## Not implemented by A

- Sandbox lifecycle 실행
- Agent/attack/replay worker
- Contract validator 및 Gateway
- Oracle/Finding/Gate/Decision 계산

## Remaining A stages

- G2: Agent/Release/Manifest/Fingerprint API
- G3: TestRun persistence, ExecutionEvent, Evidence/Audit, SSE/polling
- G4: Attestation projection
- G5: A-owned frontend
- G6: full verification and handoff
