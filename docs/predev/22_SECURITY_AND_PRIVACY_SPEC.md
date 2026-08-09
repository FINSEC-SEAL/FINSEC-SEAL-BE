# Security and Privacy Specification

## 1. Security posture

FINSEC SEAL 자체도 보안 제품이라는 이유만으로 신뢰하지 않는다. MVP는 합성 데이터로 위험을 제한하되 release/approval/evidence 무결성, arbitrary egress 방지, resource/cost abuse를 P0로 다룬다.

## 2. Security requirements

| ID | 요구사항 | 구현 통제 | 측정 가능한 Acceptance |
|---|---|---|---|
| SEC-01 | Synthetic data only | fixture generator/allowlist, 실재형식 금지, upload 안내 | test fixture scan에서 real-like PII 0; production seed source 고정 |
| SEC-02 | Secret server-side only | managed secret store, worker env reference, frontend 번들 금지 | secret canary가 repo/build/log/HTTP response에 0 |
| SEC-03 | Raw prompt/output 최소화 | event에는 digest/metadata, debug OFF | default Run에서 raw system prompt event 0 |
| SEC-04 | Classification redaction | field registry + pattern detector | SENSITIVE_PII/SECRET canary UI/SSE/report 0 |
| SEC-05 | Input trust labels | Document UNTRUSTED, LoanPolicy TRUSTED_INTERNAL, Tool registry integrity | 모든 MODEL_REQUEST metadata에 source trust summary |
| SEC-06 | Sandbox isolation | runId namespace composite FK, server injection | cross-run property test 10,000 queries 0 leakage |
| SEC-07 | Arbitrary URL egress 금지 | EXTERNAL_HTTP=fixed mock adapter, worker provider host allowlist | DNS/HTTP spy test에서 mock tool network call 0 |
| SEC-08 | Deterministic reset | immutable fixture digest/clone | reset 10회 digest/entity counts 동일 |
| SEC-09 | Audit append-only | insert-only DB role, sequence/hash chain | UPDATE/DELETE 권한 test deny; tamper 탐지 |
| SEC-10 | Request/schema validation | Pydantic/JSON Schema, size/depth/unknown reject | malformed corpus 100% 4xx, side effect 0 |
| SEC-11 | Release fingerprint integrity | canonical artifacts + recompute before Run | 1-byte semantic mutation 100% mismatch/abort |
| SEC-12 | Policy version integrity | approved immutable hash, If-Match | stale approval 409; altered policy 실행 0 |
| SEC-13 | Reviewer action audit | role, CSRF, actor/time/comment/base/result hash | approval마다 audit closure 100% |
| SEC-14 | LLM output schema validation | allowlist, fixed category/oracle/severity | fuzzed invalid proposal/attack 저장 0 |
| SEC-15 | Timeout/retry | LLM45s/Tool5s/Case90s/Run20m; limited retry | hung dependency가 한도를 초과하지 않음 ±10% |
| SEC-16 | Rate/concurrency/cost | session quota, active run unique, token/case/USD budget | duplicate/budget E2E가 409/stop, 중복 side effect 0 |
| SEC-17 | Held-out isolation | DB view/credential/DTO split/canary | patch/log/export canary occurrence 0 |
| SEC-18 | Gateway non-bypass | single dispatcher/package rule | architecture test 위반 시 build fail |
| SEC-19 | Fail closed, honest metrics | integrity failure API 미호출 + INCONCLUSIVE | failure가 ABR numerator에 포함되는 사례 0 |
| SEC-20 | Official-certification disclaimer | immutable report/UI component | 모든 decision/report snapshot test에서 한·영 문구 존재 |

## 3. Web/API security

- HTTPS only, HSTS on competition domain, secure headers(CSP, frame-ancestors none, nosniff, referrer-policy).
- Same-site session; CSRF token on mutations. Demo public access라도 approval scope는 per-session workspace에 국한.
- authorization은 route 이름이 아니라 workspace FK predicate로 적용. UUID는 권한이 아니다.
- CORS는 competition origin exact allowlist; wildcard/credentials 조합 금지.
- DB query parameterization; JSONPath/filter allowlist. Manifest JSON을 SQL/템플릿 코드로 실행하지 않는다.
- Error response에 stack trace/SQL/provider secret/prompt 원문 금지.
- Dependency lockfile, image scanning, minimal non-root container, read-only filesystem(temporary dir만 writable).

## 4. LLM/provider security

- provider endpoint는 config allowlist이며 manifest로 변경 불가.
- API key는 worker만 읽고 request/event에 포함되지 않는다.
- Prompt는 system/trusted policy/untrusted document 경계를 명시하되 이 구분을 enforcement로 간주하지 않는다.
- tool call max 8/TestCase, model requests max 6, output/token cap.
- structured outputs는 strict schema; parse failure는 최대 1 repair attempt 후 error.
- provider retention/region 조건은 배포 전에 사람이 확인한다. 합성 데이터만 보내도 contract terms를 검토한다.
- chain-of-thought를 요청하지 않고 provider가 반환해도 저장하지 않는다.

## 5. Sandbox and egress

- baseline side effect는 namespaced PostgreSQL rows에만 발생.
- LoanDecision baseline mutation도 합성이며 Run 종료 후 sealed evidence, TTL purge.
- Mock EXTERNAL_HTTP는 URL label/body digest를 DB collector에 기록하는 함수이며 socket client가 없다.
- API/web container는 outbound default deny를 목표로 하고, worker만 provider host/port 443.
- redirect, DNS rebinding, `file://`, metadata IP 문제는 fixed adapter로 surface 자체를 제거.

## 6. Privacy/data lifecycle

| Data | 저장 | 기본 retention | 접근 |
|---|---|---:|---|
| Manifest/prompt | encrypted + hash | release lifetime | Developer/Reviewer, audit |
| Synthetic document/customer | namespace | terminal 후 7일 | Run worker/Reviewer evidence |
| Raw provider debug | default 없음 | local explicit 24h | local operator |
| Redacted events/oracle/findings | DB append-only | 대회 종료+90일 | Reviewer/Governance |
| Held-out payload | encrypted | suite lifetime | execution worker; security owner |
| Attestation | immutable JSON/HTML | release lifetime | authorized viewer/public demo synthetic |
| Session/analytics | pseudonymous | 30일 | operator |

실제 PII가 입력됐다고 의심되면 Run을 중단하고 document를 quarantine, log export를 막고 operator incident 절차로 삭제/rotation을 수행한다. MVP UI에 실제 데이터 업로드 금지를 명시한다.

## 7. Audit and reviewer ownership

논리 역할: `AGENT_DEVELOPER`, `AI_SECURITY_REVIEWER`, `AI_GOVERNANCE_REVIEWER`, `DEMO_VIEWER`. P0 demo에서는 한 세션에 reviewer 역할을 줄 수 있으나 각 승인에 `demoMode=true`를 표시한다. production-like mode에서는 proposer와 approver separation을 P1로 강제한다.

Approval/decision/invalidation/reset에는 actor, role, session, request trace, idempotency key, old/new hash, comment, time, result를 기록한다. 승인 삭제/수정 API는 없다.

## 8. Incident conditions

즉시 Run 중단/배포 차단:

- real-like PII/secret detection.
- arbitrary network connection from mock adapter.
- cross-namespace row access.
- event/artifact/contract hash mismatch.
- held-out payload in patch request/log.
- unauthorized decision upgrade or missing disclaimer.

Operator는 affected Run/Release를 NEEDS_REVALIDATION, secret 의심 시 rotate, namespace seal, evidence snapshot, 원인과 복구를 audit한다.

## 9. Non-functional requirements

| NFR | Acceptance criterion |
|---|---|
| Reproducibility | 같은 fixtureVersion reset 10회 digest 동일; Run metadata 100% 필수 필드 |
| Auditability | representative Run 필수 event chain completeness 100%, approval closure 100% |
| Explainability | 모든 deny/decision에 versioned reason/rule/input fraction; `UNKNOWN` reason 0 |
| Test isolation | concurrent 20 namespaces에서 cross-read/write 0 |
| Review availability | 대회 평가창 월 기준 99.5% 목표; demo health precheck 60초 이내 |
| Error recovery | worker loss 후 2분 내 lease recovery, completed Tool side effect 중복 0 |
| Progress visibility | event commit 후 UI p95 2초 이내, reconnect 누락 0 |
| Cost control | Run budget 초과 청구 시작 전 stop; actual/estimated cost 기록 100% |
| Provider failure | timeout/retry 후 명시 ERROR/DEGRADED; 거짓 PASS 0 |
| Privacy | secret/critical value log canary 0, debug retention 자동 만료 |
| Maintainability | domain modules dependency rule CI, OpenAPI/DB/schema compatibility tests |
| Performance | policy p95≤20ms; read API p95≤500ms; 50-case run orchestration overhead≤10% |
| Accessibility | 핵심 flow keyboard 완주, automated WCAG AA critical violation 0 |

## 10. Pre-deploy security review

- threat model/egress diagram이 실제 배포와 일치.
- source map/environment/frontend bundle secret scan.
- authz/CSRF/IDOR/idempotency/rate test.
- database roles/migrations/backup restore.
- provider terms/retention/region 확인.
- disclaimers/recorded demo 표시 확인.

