# Deployment and Operations Plan

> Backend runtime과 버전은 `docs/A_ARCHITECTURE_BASELINE.md`를 우선한다. FastAPI는 stateless AI
> service이며 Core API와 PostgreSQL migration은 Spring Boot가 소유한다.

## 1. 목표 architecture

| Layer | Local | Competition |
|---|---|---|
| Frontend | React/Vite dev server | managed static hosting/CDN |
| Core API | Spring Boot 4.1.1 / Java 21 | managed container web process |
| AI service | stateless Python service | managed stateless container process |
| Worker | Core API와 독립 실행 계약 | managed container worker process |
| DB | PostgreSQL 17.11 Docker/local | managed PostgreSQL 17, private/TLS |
| Secrets | `.env.local` ignored | platform secret store |
| LLM | provider adapter/mock | approved provider endpoint |

Core API가 상태와 migration의 단일 소유자다. AI service는 DB를 직접 소유하지 않으며 stateless
request/response 경계를 유지한다. Redis/Kafka/Kubernetes는 MVP 범위에 없다.

## 2. Environment configuration

필수 config는 이름만 정의하고 값은 secret store에 둔다.

- `APP_ENV`, `PUBLIC_BASE_URL`, `DATABASE_URL`(secret), `SESSION_SIGNING_KEY`(secret).
- `LLM_PROVIDER`, `LLM_BASE_URL`(allowlisted), `LLM_API_KEY`(secret), `LLM_MODEL_ID`.
- `DEMO_MODE=true`, `DEMO_FIXTURE_VERSION`, `MAX_ACTIVE_RUNS`, `RUN_BUDGET_*`.
- `RAW_MODEL_LOGGING=false`, `SANDBOX_RETENTION_DAYS=7`, `EVIDENCE_RETENTION_DAYS=90`.

Frontend에는 public API base와 build version만 노출한다. secret/non-public DB/provider config를 `VITE_*`에 넣지 않는다.

## 3. Local bootstrap sequence

1. dependency versions 고정 및 PostgreSQL 시작.
2. DB migration apply; schema version health 확인.
3. synthetic fixture seed와 digest verify.
4. mock provider 또는 개인 server-side key 설정.
5. API/worker/frontend 시작.
6. `/health/live`, `/health/ready`, `/demo/status` 확인.
7. smoke: N-001 → FA-02 baseline → contract deny.

README 구현 단계에서 copy-paste command를 추가하되 지금 문서는 코드/명령을 확정하지 않는다.

## 4. CI/CD (대회 배포 수준)

1. lint/type/unit/schema/architecture/security canary tests.
2. backend/frontend build, dependency/image scan.
3. ephemeral DB migration + seed/integration/E2E.
4. immutable image/build id 생성.
5. staging deploy → Golden Flow smoke.
6. competition production deploy, migration backward-compatible 확인.
7. post-deploy smoke/health; 실패 시 이전 image rollback.

실제 금융회사 CI integration은 비범위다. 이 pipeline은 FINSEC 앱 자체 배포용이다.

## 5. Database migration/backup

- expand/contract migration: column add nullable/default → app deploy → backfill → later constraint.
- deployment당 migration 1회, advisory lock, timeout 5분.
- managed daily backup + point-in-time recovery 가능 설정 권장.
- 대회 전날 수동 logical backup과 restore rehearsal. 목표 RPO 24h, RTO 2h(MVP).
- audit/event table 변경은 backward reader를 유지하고 schemaVersion을 올린다.

## 6. Health/readiness

- `/health/live`: process event loop only.
- `/health/ready`: DB query, migration version, fixture availability; provider 장애는 `DEGRADED`지만 read-only console은 ready.
- `/demo/status`: API, worker heartbeat, provider, fixture digest, seed release, active run.
- Worker heartbeat 30초; 90초 이상이면 ready degraded.

## 7. Observability

- structured operational logs: timestamp, level, service, buildId, traceId/runId, event, duration, errorCode; raw payload 금지.
- metrics: request count/latency/5xx, worker queue/lease, provider latency/error/token/cost, run duration/error, policy latency, DB connections, SSE clients.
- alerts: readiness 5분 failure, 5xx>5%, worker heartbeat lost, DB 80%, cost budget 80%, integrity/security incident 즉시.
- product security evidence는 execution_event DB; 일반 app log를 Oracle source로 쓰지 않는다.

## 8. Competition availability plan

- 평가 기간 전 Golden Demo 3회 연속 dry run과 reset digest 확인.
- seed release/test suite/contract는 deployment artifact version에 pin.
- cold start를 줄이기 위해 최소 instance 1, DB connection pool bounded.
- active run global cap과 per-session cap 1. queue position 표시.
- provider 장애 시 curated seed/recorded run fallback을 명확히 라벨하고 live 실행처럼 표시하지 않음.
- 평가 URL에 불필요한 회원가입 없음. read/demo session 자동 발급, abuse rate limit.

## 9. Failure recovery runbook

| Failure | 탐지 | 자동 동작 | 운영자 동작 |
|---|---|---|---|
| LLM timeout | adapter metric | 2 retry 후 case ERROR | provider/status 확인, mock fallback 여부 결정 |
| Worker crash | lease heartbeat | 90초 후 safe resume | duplicate side effect audit |
| SSE disconnect | UI heartbeat | reconnect/polling | server issue 시 read-only results |
| DB unavailable | readiness | new runs reject, current fail safe | managed failover/restore |
| Fixture mismatch | clone verify | Run abort, no Gate | seed artifact 재배포 |
| Hash integrity mismatch | pre-run verify | release invalidate | evidence preserve/root cause |
| Cost budget reached | usage event | graceful stop | scope/trials 조정(기존 result 불변) |
| Demo reset collision | active run constraint | 409 | cancel/wait, 강제 삭제 금지 |

## 10. Retention/cleanup

- terminal Sandbox namespace 7일 후 purge job; sealed summary/evidence digest 유지.
- raw debug 24시간, session analytics 30일, core evidence 90일 이상.
- cleanup은 explicit namespace id 목록을 먼저 select/audit하고 batch delete. broad path/database destructive command 금지.
- P0 사용자 삭제 기능은 합성 data뿐이므로 제공하지 않는다.

## 11. Rollback

앱 image rollback은 가능하지만 DB downgrade migration은 하지 않는다. backward-compatible schema로 이전 image가 읽을 수 있어야 한다. Gate/oracle version을 rollback해도 이미 확정된 Decision은 재계산/변경하지 않으며 새 evaluation으로 남긴다.

## 12. Go-live checklist

- TLS/domain/headers/CORS/session/CSRF.
- DB private/TLS/backup/roles/migration.
- provider allowlist/key rotation/budget.
- mock adapter network spy test.
- Demo load/reset/live runs, report disclaimer.
- monitoring contact와 recorded fallback.
