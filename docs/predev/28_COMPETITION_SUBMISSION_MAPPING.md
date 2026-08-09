# Competition Submission Mapping

## 1. 목적

공모전 기획서·기능명세서·발표자료에 이 설계의 어느 내용을 옮길지 정한다. 실제 제출 양식의 문항명/분량이 공개되면 이 매핑의 target column만 조정한다. 증거 없는 실험값과 공인 인증 표현은 금지한다.

## 2. 기획서 매핑

| 제출 섹션 | Source | 옮길 핵심 | 권장 시각자료 |
|---|---|---|---|
| 한 줄 아이디어 | `01` | 금융업무 문맥 기반 pre-release Agent assurance | 한 문장 + Internal badge |
| 문제/배경 | `02`, `05`, `13` | Agent의 Tool/API side effect, case/applicant/field/human boundary | 권한 chain, 피해 연결 표 |
| 타깃 사용자 | `01`, `03` | Developer/Security/Governance reviewer JTBD | 3 persona 카드 |
| 해결 방식 | `08`, `12`, `15`, `16` | Hybrid AI + deterministic gateway/oracle | Component/sequence diagram |
| 핵심 차별화 | `01`, `02` | financial context, business object, field purpose, human-only, replay+regression, evidence | 6-point comparison |
| 대표 Use Case | `05`, `14`, `21` | Loan Document Review, cross-customer Demo | before/after screenshot |
| AI 활용 | `03`, `08`, `18` | manifest interpretation, variant, contract/proposal/root-cause 후보 | AI vs deterministic 책임 표 |
| 성과/검증 계획 | `18`, `19` | paired protocol, exact metrics/gate | TBD result table; 실행 후 수치만 |
| 기대효과 | `01`, `02` | 실제 effect 가시화, review 속도, change evidence | 문제→증거→결정 flow |
| 시장/확장 | `02`, `04` | 단일 업무 P0, 다른 template/engine은 P2 | now/next/later |
| 리스크/윤리 | `22`, `27`, `29` | synthetic only, disclaimer, held-out, overclaim 방지 | risk/control table |

## 3. 기능명세서 매핑

| 제출 기능군 | Source | 포함할 ID/세부 |
|---|---|---|
| Agent Release 등록 | `06 FS-01/12`, `10`, `11` | manifest, raw+hash, diff/fingerprint/revalidation |
| Sandbox | `05`, `09`, `23` | fixture, run namespace, 7 Mock systems, reset |
| Attack Engine | `14`, `18` | template→intent→LLM variant→validation; partitions |
| Agent Runtime/Trace | `08`, `17` | controlled tool loop, observable events/SSE |
| Oracle | `15` | input/output/reason/evidence, no LLM judge |
| Safety Contract | `12`, `16` | schema, 10 checks, approval, first deny |
| Patch & Replay | `06 FS-05~07`, `20` | proposal only, human approval, comparability |
| Regression/Gate | `18`, `19` | normal tasks, formulas, internal thresholds |
| Report | `06 FS-10`, `19`, `20` | exact artifact/evidence/reviewer/disclaimer |
| Demo/Operations | `21`, `23` | one-click/reset/fallback/readiness |

## 4. Architecture/technical appendix mapping

- Context/Component/Trust/Deployment: `08` Mermaid를 제출 스타일로 단순화하되 신뢰 경계는 삭제하지 않는다.
- ERD: `09`에서 Release→Run→CaseRun→Event/Oracle/Finding/Decision spine과 Sandbox namespace만 발췌.
- API: `10` endpoint catalog에서 Golden Flow 12개만 본문, 전체는 appendix.
- State: `07` Release/TestRun/Finding/Patch state.
- Security/Privacy/NFR: `22`의 measurable criteria.
- 개발 계획: `24` vertical slices/dependency/cut order.
- 테스트: `25` P0 E2E와 `18` paired protocol.

## 5. 발표 자료 권장 10장

| Slide | Message | Source |
|---:|---|---|
| 1 | 금융 Agent release 전 “행동”을 검증 | `01` |
| 2 | Tool permission만으로 부족한 business context | `02/05` |
| 3 | Loan Document Review와 금지 경계 | `05` |
| 4 | 악성 문서 → 실제 Mock side effect | `14/21` |
| 5 | Hybrid architecture: AI candidate / code decision | `08/15` |
| 6 | Safety Contract + Policy Gateway | `12/16` |
| 7 | Baseline vs Replay + 정상 200 | `20/21` |
| 8 | Held-out/Regression/Metrics/Gate | `18/19` |
| 9 | Release Evidence/Revalidation | `11/19` |
| 10 | MVP scope, roadmap, disclaimer | `04/24/29` |

## 6. 제출 문구 가이드

### 권장

- “Broad Service Account / Tool-level Permission Baseline에 금융 업무 문맥 제약을 추가해 비교한다.”
- “합성 Sandbox API 응답과 state diff를 deterministic Oracle로 판정한다.”
- “AI는 후보를 생성하고, 정책 강제·성공 판정·Release Gate는 결정적 코드가 담당한다.”
- “내부 Release Attestation이며 공식 인증이 아니다.”

### 금지/수정

| 금지 표현 | 이유 | 대체 |
|---|---|---|
| “기존 RBAC는 안전하지 않다” | strawman | “RBAC/service permission을 business-context scope로 보완” |
| “모든 prompt injection 차단” | 범위/보장 과장 | “FA-01~05 P0 suite에서 actual effect 검증” |
| “금융보안원 인증/준수” | 권한 없음 | “공개 원칙 참고 Crosswalk” |
| “자동 패치” | production 변경 오인 | “Policy Patch Proposal + Reviewer Approve & Retest” |
| “AI 안전 점수 95점” | 근거 불명 | “ASR 0/n, NTSR n/d 등 실제 fraction” |
| “실제 고객정보 유출 시연” | 사실 아님/위험 | “합성 고객정보 Mock side effect” |

## 7. 결과 수치 삽입 통제

실험 결과는 다음을 모두 충족할 때만 제출물에 넣는다.

1. Attestation의 exact Release/Contract/Suite/Sandbox fingerprint가 있음.
2. numerator/denominator와 ERROR/INCONCLUSIVE count가 함께 있음.
3. evidence Run link/hash가 있음.
4. Baseline/SEAL comparability가 true.
5. `TBD_AFTER_RUN` placeholder를 사람이 evidence와 대조 후 교체.

## 8. 제출 전 최종 체크

- Product name/Agent/use case/Tool/FA/reason/state가 설계와 일치.
- 실제 구현되지 않은 P1/P2를 현재 기능처럼 쓰지 않음.
- 화면의 Recorded/Live label이 발표 설명과 일치.
- 모든 보고서·마지막 slide에 disclaimer.
- 공식 기관 로고·인증 seal 형태 사용 금지.

