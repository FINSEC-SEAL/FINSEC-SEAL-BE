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
- terminal Run/Case child graph 및 Event commit 순서 DB row-lock 봉인

### G2 — Agent, Release, Manifest and Fingerprint

- Agent 생성/조회/수정/archive API
- 2 MB strict Manifest validation: unknown field, semantic version, digest, Tool adapter allowlist,
  JSON Schema remote ref/regex 제한, trusted RAG, no-egress, human-only boundary 검사
- RFC 8785 JCS + UTF-8 NFC/LF 정규화와 deterministic component/agent/release fingerprint
- system prompt AES-256-GCM 암호화 저장; Release row에는 redacted manifest만 저장
- derived ReleaseArtifact와 immutable Tool/RAG catalog/link를 같은 transaction에 저장
- component digest 기반 redacted semantic diff와 저장 artifact integrity 재검증
- 최신 ReleaseDecision을 참조하는 append-only manual/contract-change invalidation evidence
- 모든 mutation에 24시간 durable `Idempotency-Key` 계약. 같은 요청은 status/body/Location/trace를
  그대로 replay하고 다른 body는 409, 미완료 reservation은 fail-closed 처리

## API usage

모든 POST/PUT/DELETE 요청은 `Idempotency-Key`가 필요하다. 현재 인증 구현 전 actor scope는
`X-Actor-Id`이며 생략하면 `demo-user`를 사용한다.

```bash
curl -sS -X POST http://localhost:8080/api/v1/agents \
  -H 'Content-Type: application/json' \
  -H 'Idempotency-Key: agent-create-001' \
  -d '{"agentKey":"loan-document-review-agent","name":"Loan Review Agent","purposeSummary":"Document completeness only"}'

curl -sS -X POST http://localhost:8080/api/v1/agents/{agentId}/releases \
  -H 'Content-Type: application/json' \
  -H 'Idempotency-Key: release-create-001' \
  --data-binary @src/test/resources/fixtures/valid-release-manifest.json

curl -sS -X POST http://localhost:8080/api/v1/releases/{releaseId}:validate \
  -H 'Idempotency-Key: release-validate-001' -d '{}'

curl -sS -X POST http://localhost:8080/api/v1/releases/{releaseId}:analyze \
  -H 'Idempotency-Key: release-analyze-001' -d '{}'

curl -sS http://localhost:8080/api/v1/releases/{releaseId}/fingerprint
curl -sS 'http://localhost:8080/api/v1/releases/{releaseId}/diff?against={olderReleaseId}'
```

주요 read endpoint는 `GET /api/v1/agents`, `GET /api/v1/agents/{id}`,
`GET /api/v1/agents/{id}/releases`, `GET /api/v1/releases/{id}`다.

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

- G3: TestRun persistence, ExecutionEvent, Evidence/Audit, SSE/polling
- G4: Attestation projection
- G5: A-owned frontend
- G6: full verification and handoff
