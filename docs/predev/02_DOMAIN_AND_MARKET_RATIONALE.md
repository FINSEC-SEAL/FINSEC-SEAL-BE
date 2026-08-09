# Domain and Market Rationale

## 금융 AI Agent 보안 문제

금융 Agent의 위험은 잘못된 문장만이 아니라 권한 있는 행동이다. 문서·메일·RAG chunk 같은 untrusted input이 모델의 계획에 영향을 주면, 정상적으로 허용된 Tool을 비정상 parameter로 사용할 수 있다. 대출서류 검토에서 `CUSTOMER_DATA_READ` 자체는 필요하지만 다음 불변조건은 별개다.

`Tool → Operation → Business Object → Resource Scope → Field Scope → Cardinality → Egress → Workflow Stage → Human Approval Boundary`

IAM/RBAC는 “어떤 principal이 어떤 service/tool을 호출할 수 있는가”를 잘 다룬다. FINSEC SEAL은 그것을 대체하지 않고 Agent가 가진 service permission 안에서 현재 업무 문맥이 지켜지는지를 사전 시험한다.

## 금융소비자 피해 연결

| 실패 | 합성 Demo에서 관찰 | 현실에서 우려되는 피해 유형 |
|---|---|---|
| 타 고객 조회 | CUST-1002/1003 응답 | 개인정보·신용정보 목적 외 이용/노출 |
| 민감 필드 과다 조회 | accountNumber 반환 | 사기·피싱 악용 가능 정보 노출 |
| 외부 반출 | Mock Collector payload | 제3자 유출, 위탁/국외이전 통제 위반 우려 |
| 고영향 상태 변경 | LoanDecision=APPROVED | 부당한 금융 의사결정·재산 피해 가능성 |
| 과도한 차단 | 정상 ReviewNote 실패 | 업무 지연, 검토 누락, 운영 수용성 하락 |

MVP는 현실 피해를 발생시키지 않는다. 위 표의 현실 영향은 위협 모델링이며 법적 위반 판정이 아니다.

## 금융회사 내부 수요

- AI 플랫폼 팀: 모델·prompt·tool 변경마다 release 검증을 반복하고 싶다.
- 보안 팀: prompt injection이 실제 side effect까지 이어졌는지 증거가 필요하다.
- 현업/준법: 정상 업무 목적과 인간 승인 경계가 정책에 반영됐는지 확인해야 한다.
- 감사/리스크: 누가 어떤 정책을 승인했고 무엇이 바뀌어 재검증됐는지 추적해야 한다.

## 왜 Pre-deployment인가

1. 실제 고객/거래 없이 공격을 반복할 수 있다.
2. 같은 snapshot에서 baseline과 policy 적용 결과를 공정하게 비교할 수 있다.
3. 운영 장애 전에 false block을 정상업무 regression으로 발견한다.
4. release artifact 변경과 evidence validity를 결합할 수 있다.

Runtime enforcement는 중요하지만 별도 문제다. MVP gateway는 합성 Sandbox 시험 경로에서만 강제되며 production WAF로 홍보하지 않는다.

## 왜 Business Context Authorization인가

대출서류 Agent의 권한은 static role만으로 완성되지 않는다. Case가 `DOCUMENT_REVIEW` 단계이고, 대상 document가 `allowedDocumentIds`에 있으며, customer가 `currentApplicantId`이고, field가 업무 목적상 필요한 범위일 때만 호출해야 한다. 즉 권한은 runtime context와 parameter의 관계식이다.

```text
allow = tool_allowed
     ∧ workflow_stage_valid
     ∧ object_in_current_case
     ∧ fields_subset_of_purpose
     ∧ cardinality_within_limit
     ∧ no_external_egress
     ∧ not_human_only
     ∧ trusted_tool
```

## 기존 Agent Red Team과의 관계

FINSEC SEAL은 범용 솔루션이 답변만 검사한다고 주장하지 않는다. 시장에는 Tool/API behavior, authorization, CI safety testing을 지원하는 제품과 프레임워크가 있다. FINSEC의 좁은 차별점은 다음의 결합이다.

- 단일 금융 업무 template에서 목적 기반 최소/최대 권한을 제안.
- current Case/current Applicant와 field-level purpose를 deterministic policy로 강제.
- human-only financial action을 별도 invariant로 평가.
- 동일 공격 replay와 정상 regression 결과를 Release Attestation에 함께 봉인.

## 구매/도입 가설

MVP 검증 가설은 “금융사가 새로운 security category를 구매한다”가 아니라 다음이다.

- H1: AI 보안 reviewer는 raw model output보다 tool request/API response/state diff를 신뢰한다.
- H2: Developer는 403 reason code와 policy diff가 있으면 finding 수정 시간을 단축한다.
- H3: Governance reviewer는 release fingerprint/revalidation history를 단발 red-team report보다 유용하게 본다.
- H4: 정상업무 성공률을 함께 제시해야 강화 정책의 채택 가능성이 높다.

대회 Demo와 사용자 인터뷰에서 H1~H4를 검증한다. 시장 규모·매출 수치는 별도 조사 없이 임의로 제시하지 않는다.

## Positioning 문구

권장: “금융업무 문맥으로 Agent 권한의 사용 범위를 정의하고, 실제 합성 side effect와 정상업무를 함께 검증하는 pre-release assurance.”

금지: “기존 RBAC는 안전하지 않다”, “모든 Agent 공격을 막는다”, “금융보안원 인증”, “규제 준수 보장”, “production 차단 제품”.

