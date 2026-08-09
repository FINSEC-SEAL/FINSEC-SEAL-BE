# Risk Register

## 1. 평가 척도

- 가능성/영향: 1(낮음)~5(매우 높음). Score=`L×I`.
- 15~25 Critical attention, 8~14 High attention, 1~7 Monitor.
- 상태: OPEN, MITIGATING, ACCEPTED(P2만), CLOSED.

## 2. 기술·제품 리스크

| ID | Risk | L | I | Score | 예방/완화 | Trigger / Contingency | Owner |
|---|---|---:|---:|---:|---|---|---|
| R-01 | 모델 비결정성으로 같은 공격 결과가 흔들림 | 4 | 4 | 16 | critical 3 trials, exact metadata/paired snapshot, distribution | agreement<80% → REVIEW, Demo curated model/temp 고정 | AI |
| R-02 | LLM이 공격 Tool call을 하지 않아 대표 취약점 시연 실패 | 4 | 5 | 20 | prompt/tool descriptions/seed 문서 사전검증, provider mock contract test | live 실패 → 동일 build의 recorded run 표시(명시적 label) | AI/Product |
| R-03 | custom Policy Evaluator 구현 오류 | 3 | 5 | 15 | ordered pure functions, property/fuzz/golden tests, response defense-in-depth | any bypass/cross-scope → release freeze; P0 rule 축소 | Security |
| R-04 | Runtime이 Gateway를 우회하는 호출 경로 | 2 | 5 | 10 | single dispatcher, adapter visibility, architecture/network spy tests | direct adapter call 탐지 → build fail | Backend/Security |
| R-05 | Oracle false positive/negative 또는 evidence 누락 | 3 | 5 | 15 | before/event/after triad, corrupt-input INCONCLUSIVE, versioned golden tests | evidence gap → REVIEW, Attestation 차단 | Security/Data |
| R-06 | Held-out leakage로 patch 과적합 | 3 | 5 | 15 | DB role/view, DTO enum, canary audit | canary hit → test invalidation, suite rotation | Security |
| R-07 | Snapshot/Run isolation 실패 | 2 | 5 | 10 | composite namespace FK, clone digest, concurrency property tests | mismatch/cross-read → all active runs abort, namespaces seal | Backend/Data |
| R-08 | baseline의 의도적 broad permission이 실제 network/데이터에 연결 | 2 | 5 | 10 | mock-only adapter, no URL/network route, synthetic sentinel | socket/real-like PII detection → incident stop | Security/Ops |
| R-09 | 정책이 모든 Tool을 차단해 거짓 안전 | 3 | 4 | 12 | financial template minimum permission, normal 20/FBR gate | NTSR<80/FBR>20 → BLOCKED | Security/Product |
| R-10 | fingerprint canonicalization이 semantic change를 놓침 | 3 | 5 | 15 | artifact별 hash, RFC8785/NFC rules, mutation suite | collision/missed trigger → manual invalidate/new version | Backend/Security |
| R-11 | model alias/provider drift로 paired comparison 무효 | 3 | 4 | 12 | resolved model id 기록, mismatch comparability=false | mismatch → REVIEW/re-run pinned model | AI/Ops |
| R-12 | event 순서/중복/누락으로 trace 신뢰 저하 | 3 | 4 | 12 | DB sequence/unique/hash/outbox/idempotency | gap → REVIEW, REST snapshot fallback | Backend |
| R-13 | LLM/API 비용 또는 timeout이 full suite 방해 | 4 | 4 | 16 | budget/cap/cache seed/scoped Demo, timeout/retry | 80% budget → stop mutations; core Seed/normal 우선 | AI/Ops |
| R-14 | public Demo 남용/동시 실행으로 평가 가용성 저하 | 3 | 4 | 12 | session/global concurrency, rate, warm instance | queue/5xx threshold → read-only recorded evidence | Ops |
| R-15 | Report가 공식 인증처럼 보임 | 3 | 5 | 15 | bilingual immutable disclaimer, no regulator logo/seal, copy review | 문구/디자인 오인 발견 → submission block | Product/Governance |
| R-16 | 논리 역할 단순화가 실제 separation처럼 오인 | 3 | 3 | 9 | demoMode audit/banner, Enterprise RBAC 비범위 | 질문 시 limitation 설명; 상용화 P1 | Product/Security |
| R-17 | raw prompt/log에 secret-like 데이터 | 2 | 5 | 10 | default no raw, redaction/canary, server secret only | canary hit → run quarantine/log access stop/key rotation | Security/Ops |
| R-18 | DB migration/배포 실패 | 2 | 4 | 8 | expand/contract, staging restore, immutable image | readiness fail → previous image rollback | Backend/Ops |
| R-19 | UI와 실제 API/state 불일치 | 3 | 3 | 9 | generated types, contract/E2E, traceability audit | unknown state/404 action → feature flag off | Frontend/Backend |
| R-20 | 문서 범위가 넓어 P0 Golden Flow가 늦음 | 4 | 4 | 16 | vertical slices, cut order, scope guardrail | M2/M3 지연 → FA-06/PDF/rich nav 즉시 cut | Tech Lead |

## 3. 공모전·신뢰성 리스크

| ID | Risk | L | I | Score | 완화 | Owner |
|---|---|---:|---:|---:|---|---|
| C-01 | 문제 설명이 prompt injection detector로 오해됨 | 3 | 4 | 12 | actual side effect, business scope chain, not-list 반복 | Product |
| C-02 | 기존 RBAC/Agent security를 strawman 처리 | 3 | 4 | 12 | baseline 명칭 고정, 보완 layer 설명, 비교 claims review | Product/Security |
| C-03 | AI 활용이 장식처럼 보임 | 3 | 4 | 12 | AI 후보 생성 5개 vs deterministic final 8개 역할을 UI/architecture에 분리 | AI/Product |
| C-04 | 임의 안전 점수/가짜 실험값으로 신뢰 저하 | 2 | 5 | 10 | exact fraction/count, TBD placeholder, evidence link 필수 | Data/Governance |
| C-05 | 60초 내 흐름 이해 실패 | 3 | 5 | 15 | Release Detail, stepper, before/after, usability rehearsal | UX/Product |
| C-06 | 평가 당일 provider/network 장애 | 3 | 5 | 15 | health preflight, curated seed, explicitly recorded evidence fallback | Ops |
| C-07 | 규제 준수/금융보안원 인증 주장 오인 | 2 | 5 | 10 | `29` crosswalk disclaimer, 출처/버전, 제출 copy gate | Governance |
| C-08 | 합성 공격 피해가 현실 피해처럼 과장 | 3 | 3 | 9 | “Mock/Synthetic” badges와 위협 시나리오/실제 영향 구분 | Product |
| C-09 | 발표 시간에 reset/full suite 지연 | 3 | 4 | 12 | representative scoped live + full sealed evidence, warm fixture | Ops/Product |
| C-10 | P0 문서와 실제 구현 불일치 | 4 | 4 | 16 | OpenAPI/schema source, `26` audit, Definition of Done | Tech Lead |

## 4. Top 5 technical risks to review weekly

1. R-02 representative Agent behavior reliability.
2. R-03 deterministic policy correctness.
3. R-05 Oracle/evidence correctness.
4. R-06 held-out isolation.
5. R-10 fingerprint/revalidation integrity.

## 5. Risk review cadence

- 매일: R-02/03/05/13/20 trigger와 M1~M6 진행.
- Slice 종료: 새 control이 threat model/traceability/test에 반영됐는지.
- 대회 전 1주/1일: C-05/06/07/09 rehearsal.
- Score 변화는 기존 행을 삭제하지 않고 `lastReviewedAt`, note(구현 시 field 추가)로 이력화한다.

