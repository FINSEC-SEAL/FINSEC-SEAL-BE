# Regulatory and Framework Reference Crosswalk

## 1. 중요 고지

> 본 매핑은 FINSEC SEAL MVP 설계를 위한 참고 Crosswalk이며 규제 준수, 법률 의견, 적합성 평가 또는 금융당국·금융보안원 등 기관의 인증을 의미하지 않는다. 적용 기관·업무·법적 지위에 따른 실제 의무는 금융회사 준법·법무·정보보호 담당자가 최신 원문으로 별도 판단해야 한다.

> This reference crosswalk supports MVP design only. It is not a compliance determination or an official certification.

기준일: **2026-08-09**. Framework는 개정될 수 있으므로 Release 제출 직전에 source version을 재확인한다.

## 2. 참고한 공식 자료

| Source | 기준 자료/상태 | FINSEC에서 참고하는 주제 |
|---|---|---|
| 금융위원회 | [2026-06-18 금융분야 인공지능 가이드라인 개정안 발표](https://www.fsc.go.kr/po010101/87142?srchCtgry=1); 보도자료상 2026-06-22 시행 예정 안내 | 책임 있는 AI, 전 생애주기 위험관리, 보안·금융안정성·인간 책임 방향 |
| 금융보안원 | [2026-06-19 금융분야 인공지능 보안 안내서](https://www.fsec.or.kr/bbs/detail?bbsNo=11977&menuNo=222) | 2026년 금융분야 AI 보안 안내서의 공식 공개본 존재와 버전 기준점 |
| 금융보안원 | [2025-06-09 AI 에이전트 보안 위협 보고서 공개](https://www.fsec.or.kr/bbs/detail?bbsNo=11700&menuNo=69) | Agent hijacking, Tool poisoning, 금융권 영향 |
| 금융보안원 | [2026-01-02 금융 AI 신뢰성·안전성 핵심 AI 전략](https://www.fsec.or.kr/bbs/detail?bbsNo=11872&menuNo=69) | AI red teaming 확대·보안성 검증 방향 |
| 금융보안원 | [2026-05-27 금융AI보안지원센터 운영 개시](https://www.fsec.or.kr/bbs/detail?bbsNo=11959&menuNo=69) | 고성능 AI 보안위협 대응 지원 방향 |
| NIST | [AI Risk Management Framework 1.0 및 공식 Resource Center](https://www.nist.gov/itl/ai-risk-management-framework), [NIST AI 600-1 GenAI Profile](https://nvlpubs.nist.gov/nistpubs/ai/NIST.AI.600-1.pdf) | GOVERN/MAP/MEASURE/MANAGE, TEVV, 기록·위험관리 |
| OWASP GenAI Security Project | [OWASP Top 10 for Agentic Applications 2026](https://genai.owasp.org/resource/owasp-top-10-for-agentic-applications-for-2026/) | goal hijack, tool misuse, identity/privilege, supply chain 등 Agentic risk |

금융보안원의 2026-06 보안 안내서 공개본은 위 표에 반영했다. 다만 이 MVP 문서는 안내서 PDF의 조항별 준수표가 아니며, 금융위원회 개정 가이드라인과 별도 위험관리프레임워크의 최신 원문·적용 범위는 구현 착수 또는 제출 직전에 다시 확보해 version/date를 기록해야 한다. 현재 문서는 보도자료와 공개 가이드의 방향을 상세 법적 요구로 확대 해석하지 않는다.

## 3. 금융 AI 원칙 ↔ FINSEC capability

| 참고 원칙/방향 | FINSEC design mapping | Evidence artifact | 한계/비준수 주장 방지 |
|---|---|---|---|
| 책임·거버넌스 | logical roles, reviewer approval, immutable ReleaseDecision | patch_approval, release_decision, audit event | Enterprise segregation/조직 책임체계 전체를 구현하지 않음 |
| 인간 감독/책임 | LoanDecision `HUMAN_ONLY`; Agent는 ReviewNote만 | Policy decision, state-diff Oracle | 실제 은행 승인 프로세스와 연결하지 않음 |
| 안전성·보안성 | FA-01~05 attack suite, Gateway, deterministic Oracle | TestRun/Oracle/Finding | 지정 threat/dataset에 대한 MVP 시험이지 포괄 안전 보증 아님 |
| 설명가능성/투명성 | first-deny reason, observable Tool/API trace, exact metric fraction | execution_event, attestation | 모델 내부 추론 설명이나 모든 AI 판단의 설명가능성을 보장하지 않음 |
| 데이터/프라이버시 | synthetic only, field purpose, redaction, egress deny | fixture digest, classification/redaction event | 실제 개인정보 처리 적법성 평가가 아님 |
| 생애주기/변경관리 | release artifacts/fingerprint/revalidation | release diff, NEEDS_REVALIDATION | 실제 금융사 SDLC/CI change approval을 대체하지 않음 |
| 안정성/유용성 | normal regression, false block, error handling | NTSR/FBR/error distribution | 금융상품 성능·공정성·소비자 결과 평가는 비범위 |

## 4. 금융보안원 공개 Agent 위협 방향 ↔ FINSEC

| 공개 위협/방향 | FINSEC category/control | Test |
|---|---|---|
| Agent hijacking | FA-01 malicious Document, context-bound Gateway | baseline actual effect + replay |
| Tool poisoning | FA-06 metadata trust/hash (P1 implementation) | ToolPoisoningOracle + effect Oracle |
| 비정상 대출 승인 등 고영향 행동 우려 | FA-05/HUMAN_ONLY/LoanDecision state oracle | baseline mutation + replay unchanged |
| AI red teaming 확대 | Seed/Mutation/Held-out/trials, deterministic evidence | paired experimental protocol |
| 신뢰성·안전성 검증 지원 | Release evidence/revalidation | Internal Attestation | 

마지막 행은 기능적 방향의 참고일 뿐 금융보안원의 평가·인증체계와 FINSEC 결과가 동등하다는 의미가 아니다.

## 5. NIST AI RMF Crosswalk

| AI RMF function/theme | FINSEC implementation | Evidence | Gap |
|---|---|---|---|
| GOVERN — 정책·책임·risk tolerance | financial template, gate policy version, reviewer ownership | ADR, approval, Decision | 조직 전체 governance/법적 책임 미구현 |
| MAP — context/use/impact | Loan Document Review purpose, actors/assets/trust boundaries | Manifest, Domain Model, Threat Model | 실제 금융사 context/stakeholder assessment 없음 |
| MEASURE — TEVV | paired baseline, held-out, normal tasks, trial distribution | TestSuite/Run/Oracle/Metrics | 좁은 합성 dataset; fairness/robustness 전체 미평가 |
| MANAGE — prioritize/respond/monitor change | critical gate, patch proposal/replay, revalidation | Finding/Contract/Decision/Attestation | production monitoring/incident response integration 없음 |
| GenAI profile — prompt/data/security risk | untrusted input label, egress, schema validation, logs | Trace/Security Spec | provider/model supply-chain assurance 제한 |

## 6. OWASP Agentic Applications Crosswalk

OWASP taxonomy는 FINSEC FA 번호와 동일하지 않다. category를 억지로 1:1 동일시하지 않고 overlap을 기록한다.

| OWASP Agentic risk theme | FINSEC coverage | Coverage level |
|---|---|---|
| Agent goal/behavior hijack | FA-01 Document indirect injection + actual Tool effects | P0 direct |
| Tool misuse/exploitation | FA-02~05 parameter/effect controls | P0 direct, Mock tools only |
| Identity/privilege abuse | broad baseline vs context policy, human boundary | P0 partial; real IAM/identity는 비범위 |
| Agentic supply chain/tool poisoning | tool description/schema/trust/fingerprint, FA-06 | design P0, runtime P1 |
| Unexpected code execution | remote adapter/module/$ref 금지 | preventive design; 공격 실행 catalog 비범위 |
| Memory/context poisoning | immutable fixture/RAG version/trust | partial; persistent memory 없음 |
| Insecure inter-agent communication | 다중 Agent/A2A 없음 | not applicable to MVP |
| Cascading/rogue agent behavior | max steps/tools/budget; single Agent | limited/not directly covered |
| Human trust/manipulation | evidence-first UI/disclaimer/reviewer approval | partial governance control |

## 7. General security principles

| Principle | FINSEC concrete rule |
|---|---|
| Least privilege | allowedTools + current applicant/case + allowed fields + max 1 + stage |
| Complete mediation | Runtime의 모든 Tool invocation이 Gateway를 통과 |
| Fail closed | contract/context/integrity 실패 시 API 미호출; metric은 INCONCLUSIVE |
| Separation of duties | AI candidate와 deterministic validator/reviewer, Agent와 human-only decision 분리 |
| Defense in depth | pre-call policy + adapter namespace + response projection + post-effect Oracle |
| Auditability | append-only ordered/hash-linked events, versioned approval/decision |
| Change management | artifact fingerprint, semantic diff, automatic NEEDS_REVALIDATION |
| Human oversight | Approve & Retest, Gate confirmation, no upward override |
| Data minimization/purpose limitation | 업무에 필요한 applicant/2 fields만 |

## 8. Evidence package for human compliance review

FINSEC가 준수 판정을 내리지는 않지만 실제 담당자의 검토를 돕기 위해 다음을 export한다.

- agent purpose/workflow/human boundary와 exact release artifacts.
- data classification/allowed object/field/egress policy.
- threat suite/version/trials/error와 actual-effect evidence.
- approved policy change/normal impact/reviewer history.
- decision rule/remaining findings/revalidation triggers.
- source Crosswalk version/date와 명시적 gap/disclaimer.

## 9. Update procedure

1. 제출 전 공식 source URL의 최신본/date/version 확인.
2. 변경된 원칙은 이 문서와 `13`, `22`, `28`에 영향 분석.
3. 법무/준법 담당자가 “참고 mapping” 표현과 disclaimer 승인.
4. 규제/가이드 change는 Product Release fingerprint 자체의 자동 trigger가 아니지만 TestSuite/Contract/Business Template 변경으로 이어지면 새 version과 재검증을 수행.
