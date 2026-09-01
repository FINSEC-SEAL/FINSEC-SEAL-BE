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
- 인스턴스 lease/heartbeat로 실행 주체를 추적하는 `PROCESSING → RECOVERY_REQUIRED`
  fail-closed 멱등성 상태 머신과 audited `RELEASE`/`COMPLETE` 운영자 복구
- 잘못된 복구 인증을 멱등성 예약 전에 거부하고, 복구 응답의 status/content type/
  Location/trace/body digest 전체를 하나의 canonical response digest로 봉인
- transaction rollback 후 메인 pool과 분리된 전용 2-connection audit pool에서 동기 commit하는
  system prompt plaintext 접근 audit(인메모리 queue 미사용)

### G3 — TestRun, Trace, Evidence and Audit delivery

- TestRun/TestCaseRun 저장 및 상태 전이 API(실행·판정 계산은 미포함)
- append-only ExecutionEvent와 Run별 단조 sequence, 이전 hash 기반 tamper-evident event chain
- transactional event outbox, publish attempt 추적, SSE resume/heartbeat와 polling history
- HMAC 기반 synthetic ID tokenization, PII/금융/신용정보 redaction, secret-like payload 저장 거부
- release/run/workspace closure를 검증하는 EvidenceReference와 scope-checked append-only AuditRecord

### G4 — Attestation projection

- D가 저장한 최신 confirmed ReleaseDecision의 exact immutable input snapshot만 사용
- A는 metric/rule/gate/decision을 재계산하지 않고 projection·integrity·export만 담당
- RFC 8785+NFC deterministic JSON document hash와 immutable JSON/HTML 저장
- 한국어/영어 내부 평가 disclaimer를 DB trigger까지 고정
- Decision invalidation 뒤 document/hash는 보존하고 응답과 HTML에 stale/NEEDS_REVALIDATION 표시
- 현재 Release lifecycle이 `VERIFYING` 등으로 다시 이동해도 불변 Decision snapshot과
  append-only invalidation이 있으면 historical Attestation을 재현
- Release row lock과 DB latest-decision guard로 Decision/Invalidation 경합을 직렬화하고,
  TestSuite/Run/Finding 출처 closure와 저장된 JSON/hash/HTML의 기대 projection 일치를 매번 재검증

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

curl -sS http://localhost:8080/api/v1/releases/{releaseId}/attestation
curl -sS 'http://localhost:8080/api/v1/releases/{releaseId}/evidence-export?format=json' -o attestation.json
curl -sS 'http://localhost:8080/api/v1/releases/{releaseId}/evidence-export?format=html' -o attestation.html
```

주요 read endpoint는 `GET /api/v1/agents`, `GET /api/v1/agents/{id}`,
`GET /api/v1/agents/{id}/releases`, `GET /api/v1/releases/{id}`다.

### Idempotency operator recovery

시간만 지났다고 원 요청을 자동 재실행하면 commit 여부를 알 수 없으므로 금지한다.
정상 응답은 `COMPLETED`, 5xx/예외이 발생한 실행은 즉시 `RECOVERY_REQUIRED`,
응답 전 인스턴스가 죽은 경우는 reservation TTL과 owner lease stale 시간이 모두 지난 후에만
`RECOVERY_REQUIRED`로 전환한다. 이 상태만 pending API에 노출된다.

복구 전에 반드시 별도 시스템/DB/업무 결과로 원 요청 결과를 확인하고,
`.env`의 `FINSEC_IDEMPOTENCY_RECOVERY_KEY`를 32 bytes 이상 random 값으로 설정한다.
`FINSEC_IDEMPOTENCY_INSTANCE_HEARTBEAT_MS`는 `FINSEC_IDEMPOTENCY_INSTANCE_STALE_AFTER`보다
충분히 짧게 유지한다(기본 5초/30초).

```bash
# 복구 대상 조회: 응답의 actor/method/path/key/requestDigest를 그대로 사용
curl -sS http://localhost:8080/api/v1/platform/idempotency-recoveries/pending \
  -H 'X-Actor-Id: operator:platform' \
  -H "X-Operator-Recovery-Key: $FINSEC_IDEMPOTENCY_RECOVERY_KEY"

# 원 작업이 실행되지 않았음을 확인한 경우에만 RELEASE
curl -sS -X POST http://localhost:8080/api/v1/platform/idempotency-recoveries \
  -H 'Content-Type: application/json' \
  -H 'Idempotency-Key: recovery-command-001' \
  -H 'X-Actor-Id: operator:platform' \
  -H "X-Operator-Recovery-Key: $FINSEC_IDEMPOTENCY_RECOVERY_KEY" \
  -d '{"actorId":"original-actor","httpMethod":"POST","requestPath":"/api/v1/agents","idempotencyKey":"original-key","requestDigest":"sha256:...","resolution":"RELEASE","verificationReference":"ops:incident/FINSEC-2026-0001"}'
```

이미 실행됐음을 확인한 경우에는 `resolution=COMPLETE`와 원래 status/contentType/Location/traceId 및
response body의 Base64를 함께 보낸다. 복구 row와 audit는 불변이며 request identity와 다른 값은 거부된다.
잘못된 운영자 키는 명령용 `Idempotency-Key`를 예약하기 전에 403으로 종료되므로,
같은 명령 키로 올바른 인증을 재시도할 수 있다.

## Run and verify

```bash
./gradlew clean test --warning-mode all
```

이 테스트는 실제 `postgres:17.11-alpine`을 시작하므로 Docker가 필요하다. H2로 대체하지 않는다.

```bash
cp .env.example .env
# FINSEC_DATA_ENCRYPTION_KEY_BASE64에 `openssl rand -base64 32` 결과 입력
# FINSEC_IDEMPOTENCY_RECOVERY_KEY에 32 bytes 이상의 random 운영자 키 입력
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

- G5: A-owned frontend
- G6: full verification and handoff
