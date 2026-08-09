# UI/UX Specification

## 1. 경험 원칙

- 일반 소비자 금융 앱이 아닌 Enterprise AI Security / Release Console.
- Release Detail에서 문제→공격→effect→root cause→contract→replay→regression→decision을 끝낸다.
- 모델의 숨은 reasoning보다 Tool/API/Event evidence를 먼저 보인다.
- 안전을 0~100 점수로 표시하지 않는다. PASS/REVIEW/BLOCKED와 실제 fraction/count를 사용한다.
- 모든 result/attestation 영역에 Internal/Not official certification 고지를 노출한다.

## 2. Information architecture

Global nav: Dashboard, Agents, Releases, Test Runs, Findings, Safety Contracts, Reports. P0에서 Dashboard/목록은 얕게 만들고 Release Detail을 깊게 구현한다.

### Release Detail tabs

1. Overview
2. Attack Tests
3. Findings
4. Safety Contract
5. Replay
6. Report

Header에는 Agent/version, fingerprint short id, lifecycle/effective status, last tested, `Run Demo`, `Reset`가 항상 보인다.

## 3. 핵심 layout

```text
┌ Agent / Release v1.0.0 ── [NEEDS/PASS] ── Run Demo ─ Reset ┐
│ Disclaimer: Internal assessment; not official certification │
├ Analyze ─ Generate ─ Baseline ─ Findings ─ Contract ─ Replay ─ Regression ─ Decision ┤
├ Tabs: Overview | Attack Tests | Findings | Safety Contract | Replay | Report          ┤
│ Main content (8 cols)                         │ Evidence/Run summary (4 cols) │
│ Trace / diff / metrics                        │ status, counts, next action   │
└───────────────────────────────────────────────────────────────────────────────┘
```

Desktop first(1280px), tablet 최소 1024px. 작은 화면에서는 evidence panel을 drawer로 바꾸되 Demo 핵심은 desktop 평가를 기준으로 한다.

## 4. Test Pipeline Stepper

`Analyze → Generate Tests → Baseline → Findings → Contract → Replay → Regression → Decision`.

각 step 상태: NOT_STARTED, ACTIVE, COMPLETED, FAILED, NEEDS_ATTENTION, SKIPPED. 클릭하면 관련 tab/anchor로 이동. server lifecycle에서 projection하며 client가 임의 완료하지 않는다.

| Step | primary API | 완료 증거 |
|---|---|---|
| Analyze | `POST /releases/{id}:analyze` | fingerprint/components |
| Generate | contracts/tests generate | suite hash/count |
| Baseline | `POST /test-runs` | baseline run terminal |
| Findings | `GET /findings` | oracle evidence/open finding |
| Contract | generate/validate/approve | approved version/hash |
| Replay | `POST /replays` | comparison all comparable |
| Regression | HELD_OUT + REGRESSION runs | required trials/metrics |
| Decision | evaluate/confirm | attestation |

## 5. Overview

- Purpose card: “서류 완전성 검토, 대출 결정 아님”.
- Release artifacts: model, prompt hash, tool count/schema hashes, RAG, contract.
- Revalidation diff/banner.
- Baseline vs SEAL metric cards: ASR fraction, unauthorized records, sensitive fields, exfil, mutation, NTSR/FBR. 값이 없으면 N/A.
- Golden Flow CTA.

## 6. Attack Tests and Execution Trace

- 왼쪽: case list(category/severity/partition/trial/outcome). Held-out payload는 실행 전 hidden.
- 중앙 lane: Agent → Tool Proposed → Policy Decision → Mock API → Side Effect → Oracle.
- 오른쪽 detail: redacted input/output, check list, state before/after, evidence digest.
- deny event는 빨간색 위험이 아니라 보호 성공을 의미하는 파란 shield badge; actual attack success는 red finding badge.
- `Attempted`와 `Succeeded`를 별도 label.

## 7. Findings

Finding detail sections: violated invariant, actual impact counts, evidence links, root cause, baseline configuration disclaimer, affected AttackCases, proposal history. Severity 근거와 “synthetic only”를 나란히 둔다.

`Generate Policy Patch Proposal`은 LLM 사용 표시와 함께 candidate임을 명시한다. Reviewer가 diff/normal impact/validator results를 본 뒤 `Approve & Retest`; confirm modal에는 base/result hash와 “Production policy is not modified” 문구가 있다.

## 8. Safety Contract

- Human-readable rule table과 canonical JSON toggle.
- Tools/scope/fields/count/egress/workflow/human/trust sections.
- version timeline: Candidate/Validated/Approved/Rejected.
- validator ERROR/WARN은 JSON pointer와 정상업무 영향으로 표시.
- approved version은 read-only.

## 9. Before / After Replay

```text
BASELINE                                 FINSEC CONTRACT
Tool: CUSTOMER_DATA_READ                Tool: CUSTOMER_DATA_READ
Policy: TOOL_LEVEL_ALLOW                Policy: DENY CUSTOMER_SCOPE...
API: 200 / 3 rows                       API: not invoked / 403 equivalent
State/effect: 2 unauthorized records    State/effect: 0
Oracle: ATTACK_SUCCESS                  Oracle: ATTACK_BLOCKED
```

상단 `Comparable` badge는 agent artifact/fixture/model/variant hash가 모두 일치하고 policy만 의도대로 다를 때 표시한다. 전체 release fingerprint는 Contract hash 때문에 다름을 tooltip으로 설명한다. 정상 control 요청 200을 같은 화면 하단에 보여 “공격만 차단”을 증명한다.

## 10. Report

- Decision banner, exact metric fractions, remaining findings, approvals, artifact hashes, revalidation triggers.
- stale report는 `NEEDS_REVALIDATION` overlay.
- JSON/HTML export. PDF는 P1.
- 한·영 disclaimer는 접을 수 없다.

## 11. Dashboard/lists (P0 light)

- Dashboard: Agent count, effective statuses, active Runs, open critical/high findings, “Start Golden Demo”.
- Agents/Releases: name/version/status/fingerprint/last tested.
- Test Runs: mode/status/progress/errors/cost.
- Findings: severity/category/status/release.
- Contracts: release/version/state/reviewer.
- Reports: decision/stale/testedAt/export.

## 12. Empty/loading/error/cancel states

| 상태 | 표현 | action |
|---|---|---|
| No release | manifest 목적 설명 | Load Demo/Create Release |
| No run | 예상 pipeline 설명, 성과값 0으로 보이지 않음 | Run Baseline |
| Loading REST | skeleton; 기존 데이터 유지 | — |
| Active run | progress fraction, current phase, elapsed/cost | View trace/Cancel |
| SSE disconnected | “Reconnecting; run continues” | polling fallback |
| LLM degraded | curated seeds 사용 여부 | Retry/Continue degraded |
| Operational failure | code/traceId/completed evidence | Resume/Retry safe cases |
| Cancelled | partial evidence, gate disabled | New Run |
| Fingerprint changed | stale banner/diff | Start Revalidation |
| Reset blocked | active run 표시 | Cancel or wait |

## 13. Accessibility

- status를 색만으로 전달하지 않고 icon/text 사용.
- keyboard stepper/tabs/table; focus visible.
- WCAG 2.2 AA contrast 목표, semantic headings/table captions, live progress는 `aria-live=polite`(과도한 event 제외).
- raw JSON/diff는 copy 가능하고 line wrap/monospace; screen reader용 요약 제공.

## 14. One-click Demo

`Run Golden Demo`는 manifest 분석부터 baseline representative attack까지 자동 진행하고 Finding에서 일시정지한다. 사용자가 `Approve & Retest`를 누르면 replay/held-out/regression/gate가 이어진다. 승인 행위는 자동 클릭하지 않는다. `Reset`은 confirm 후 seed digest를 보여주고 demo-derived data만 재생성하며 다른 사용자의 active Run에 영향을 주지 않는다.

## 15. UI acceptance

1. 처음 방문한 평가자가 60초 내 attack side effect와 contract deny를 찾을 수 있음.
2. 모든 displayed metric에 numerator/denominator tooltip.
3. raw secret/critical field 값은 DOM/network response에도 없음.
4. active/cancel/error/reconnect/reset state E2E 통과.
5. UI button이 `10`에 없는 API를 호출하지 않음.
