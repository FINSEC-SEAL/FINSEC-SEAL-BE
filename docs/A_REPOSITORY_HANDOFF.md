# A Role Repository Handoff

## 담당 결론

A의 소유 범위는 **Platform / Data / Evidence**다. A는 공통 기반, 식별자,
Release/Trace/Evidence 저장과 무결성, Audit, Attestation projection, 이를 운영하는
Frontend만 소유한다. Attack/Agent 실행, Policy/Approval 판단, Oracle/Finding/Metric/Gate/Decision
계산은 B/C/D 담당이다.

## Repository별 작업과 사용법

| Repository | A가 수정한 내용 | 사용/검증 | Branch |
|---|---|---|---|
| `FINSEC-SEAL-BE` | Spring/PostgreSQL 기반, Agent/Release, manifest/fingerprint, Run/Event/Evidence/Audit 저장, Attestation, fail-closed idempotency recovery | `.env` 설정 후 `docker compose up --build`; `./gradlew clean test --warning-mode all --rerun-tasks` | `feat/role-a-foundation` |
| `FINSEC-SEAL-FE` | A 운영 콘솔: Agent/Release/Fingerprint/Evidence/Audit/Recovery | `.env` 설정 후 `pnpm install --frozen-lockfile && pnpm dev`; `pnpm typecheck && pnpm test:coverage && pnpm build && pnpm audit --prod` | `feat/role-a-console` |
| `FINSEC-SEAL-AI` | A 실행 코드 없음. Run/Event/Evidence identity, digest, redaction, append 계약만 문서화 | AI worker 담당이 코드를 추가할 때 `docs/A_ROLE_IMPLEMENTATION.md`를 contract test 기준으로 사용 | `feat/role-a-ai-contract` |
| `FINSEC-SEAL-MOCK` | A 실행 코드 없음. fixture version/digest, deterministic reset, synthetic-only, no-egress 계약만 문서화 | Mock 담당이 fixture를 구현할 때 `docs/A_ROLE_IMPLEMENTATION.md`를 증거 snapshot 기준으로 사용 | `feat/role-a-mock-contract` |

검증에 사용한 고정 기준 SHA는 Backend `793dcbbd`, Frontend `8b14e8a5`,
AI `cc5b194`, Mock `987c69b`다. 추가 문서 커밋은 실행 코드 기준을 바꾸지 않는다.

## 로컬 실행 순서

1. Docker Desktop을 시작한다.
2. Backend의 `.env.example`을 `.env`로 복사하고 PostgreSQL password,
   `FINSEC_DATA_ENCRYPTION_KEY_BASE64`, `FINSEC_IDEMPOTENCY_RECOVERY_KEY`를 설정한다.
3. Backend에서 `docker compose up --build`를 실행하고
   `GET http://localhost:8080/actuator/health`를 확인한다.
4. Frontend의 `.env.example`을 `.env`로 복사하고 Node 24/pnpm 11에서
   `pnpm install --frozen-lockfile && pnpm dev`를 실행한다.
5. `http://localhost:5173`에서 Agent 등록 → Release manifest 등록 → validate → analyze →
   fingerprint 순으로 A 기반을 사용한다.
6. D가 confirmed Decision을 저장한 뒤에만 Evidence 화면에서 Attestation을 조회/내려받는다.

## 협업 계약

- B/C/D는 A database table을 직접 수정하지 않고 공식 API/저장 계약을 사용한다.
- 모든 mutation retry는 같은 작업에 같은 `Idempotency-Key`를 재사용한다.
- A는 타 담당이 저장한 결과를 재계산하지 않고, provenance/closure/integrity를 검증해 보존한다.
- 증거에 plaintext prompt, 실고객/금융/신용정보, credential을 저장하지 않는다.
- `STALE` Attestation은 과거 증적을 지우지 않지만 현재 Release를 인증하지 않는다.

## 상세 문서

- Backend: [`A_ROLE_IMPLEMENTATION.md`](A_ROLE_IMPLEMENTATION.md),
  [`A_SENIOR_REVIEW_LOG.md`](A_SENIOR_REVIEW_LOG.md)
- Frontend: [`A_ROLE_IMPLEMENTATION.md`](../../FINSEC-SEAL-FE/docs/A_ROLE_IMPLEMENTATION.md),
  [`A_SENIOR_REVIEW_LOG.md`](../../FINSEC-SEAL-FE/docs/A_SENIOR_REVIEW_LOG.md)
- AI: [`A_ROLE_IMPLEMENTATION.md`](../../FINSEC-SEAL-AI/docs/A_ROLE_IMPLEMENTATION.md)
- Mock: [`A_ROLE_IMPLEMENTATION.md`](../../FINSEC-SEAL-MOCK/docs/A_ROLE_IMPLEMENTATION.md)
