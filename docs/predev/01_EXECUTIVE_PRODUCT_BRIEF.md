# Executive Product Brief

## 한 문장 정의

FINSEC SEAL은 금융 AI Agent가 업무 목적 밖의 고객정보·Tool·외부 시스템·고영향 권한을 사용하는지 배포 전에 합성 환경에서 실제 공격으로 검증하고, 금융 업무 문맥 기반 Safety Contract 적용 후 공격과 정상업무를 함께 재검증해 내부 Release Decision과 증거를 만드는 Agent Release Assurance Platform이다.

## 문제

Agent는 답변을 생성하는 데서 끝나지 않고 API를 호출해 데이터를 읽고 상태를 바꾼다. `CUSTOMER_DATA_READ` 권한이 있다는 사실만으로는 “현재 Case의 신청자”, “필요한 두 필드”, “최대 1명”, “외부 전송 금지”, “대출 의사결정은 사람만”을 동시에 표현·검증하기 어렵다. 출시 전 팀은 다음을 답하기 힘들다.

- 악성 문서가 Agent의 Tool 호출을 바꿀 때 실제 데이터나 상태가 노출·변경되는가?
- parameter/business object/field/workflow 수준 통제가 실행되는가?
- 보안 정책을 강화한 뒤 정상 업무는 여전히 성공하는가?
- 변경된 Agent release가 이전 검증 증거를 재사용해도 되는가?

## Target Customer와 사용자

- Target Customer: 금융회사 AI 플랫폼·디지털 혁신·정보보호 조직, 금융 AI 솔루션 공급자.
- Agent Developer: release 등록, trace 기반 원인 확인, 수정 후 재검증.
- AI Security Reviewer: finding 증거와 patch proposal 검토·승인.
- AI Governance/Risk Reviewer: inventory, release history, 승인·재검증 기록 확인.

## Value Proposition

1. 응답 유해성 대신 실제 Tool/API side effect를 deterministic oracle로 입증한다.
2. Tool 허용 여부를 넘어 current case/applicant, field, cardinality, egress, workflow, human boundary를 검증한다.
3. Patch → replay → held-out → normal regression을 하나의 release evidence chain으로 묶는다.
4. model/prompt/tool/RAG/contract 변경 시 기존 PASS를 자동 무효화한다.
5. 심사위원이 한 번의 Demo로 “공격 성공 → 원인 → 정책 → 차단 → 정상 유지 → decision”을 이해한다.

## Why Now

금융 Agent 도입은 모델 답변 품질에서 권한 있는 행동의 안전성으로 검증 초점을 옮기고 있다. 금융업무는 개인정보·신용정보와 인간 전용 고영향 결정을 동시에 다루므로, 배포 전 반복 가능한 공격과 business-context authorization 증거가 필요하다. FINSEC SEAL은 운영 WAF나 공인 인증을 대체하지 않고 release 이전 검증 공백을 좁힌다.

## 차별화

| 축 | FINSEC SEAL의 초점 |
|---|---|
| Financial business context | `LOAN_DOCUMENT_COMPLETENESS_REVIEW` 목적에서 허용 범위를 도출 |
| Business object authorization | `case.currentApplicantId`와 요청 customerIds를 결합 검증 |
| Field-level purpose control | incomeBand/employmentStatus만 허용 |
| Human-only boundary | 승인·거절·금리·한도·거래 변경을 Agent에서 분리 |
| Evidence loop | baseline side effect와 contract replay 차단을 나란히 보존 |
| Change assurance | release fingerprint와 revalidation trigger 관리 |

범용 Agent 보안 제품도 Tool/API와 CI 검증을 지원할 수 있다. 차별성 주장은 “최초”가 아니라 금융업무 object/field/human-boundary를 release evidence에 일관되게 결합하는 좁고 깊은 MVP에 둔다.

## MVP Scope

- Loan Document Review Agent와 합성 LoanCase 세계관.
- FA-01~05 구현, FA-06 설계 및 가능하면 P1 구현.
- Broad Tool Permission baseline, approved contract replay, held-out, regression.
- deterministic gateway/oracle/metrics/release gate.
- Release Detail 중심 console과 one-click/reset demo.
- JSON/HTML Internal Release Attestation.

## 명시적 비범위

실제 고객·실제 금융 API·실제 돈 이동·공식 인증·production runtime firewall·자동 source patch·다중 Agent·다중 금융 업무·Enterprise SSO/SIEM/CI 연동은 MVP가 아니다.

## 제품 고지

> 본 결과는 FINSEC SEAL MVP의 내부 보안평가(Internal Release Attestation)이며 금융당국, 금융보안원 또는 금융보안 관련 기관의 공식 인증·보증·규제 준수 판정이 아니다.

> This is an internal FINSEC SEAL MVP security assessment and not an official certification by any regulatory or financial-security authority.

