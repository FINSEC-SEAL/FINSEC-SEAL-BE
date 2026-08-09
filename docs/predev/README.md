# FINSEC SEAL 개발 전 설계 문서

이 디렉터리는 2026 금융 AI Challenge 제출용 MVP **FINSEC SEAL**의 구현 기준이다. FINSEC SEAL은 금융 AI Agent가 업무 목적을 벗어나 고객정보·도구·외부 시스템·고영향 금융 권한을 사용하는지 배포 전에 합성 Sandbox에서 공격하고, 승인된 Safety Contract 적용 전후의 공격 및 정상업무를 재검증해 내부 Release Decision을 내린다.

> **고지:** FINSEC SEAL 결과는 내부 Release Attestation이다. 금융당국·금융보안원 또는 기타 기관의 공식 인증이나 규제 준수 판정이 아니다.

## 문서 읽는 순서

1. 제품 판단: `00` → `01` → `03` → `04`
2. 금융 세계관: `05` → `11` → `12`
3. 구현 계약: `07` → `08` → `09` → `10`
4. 보안 엔진: `13` → `14` → `15` → `16` → `17`
5. 검증·출시: `18` → `19` → `25` → `26`
6. 제품화: `20` → `21` → `23` → `24`
7. 제출·거버넌스: `22` → `27` → `28` → `29`

## 문서 인덱스

| 문서 | 구현 시 답하는 질문 |
|---|---|
| [00_ASSUMPTIONS_AND_DECISIONS.md](00_ASSUMPTIONS_AND_DECISIONS.md) | 무엇을 가정·결정·제외했는가 |
| [01_EXECUTIVE_PRODUCT_BRIEF.md](01_EXECUTIVE_PRODUCT_BRIEF.md) | 누구의 어떤 문제를 푸는가 |
| [02_DOMAIN_AND_MARKET_RATIONALE.md](02_DOMAIN_AND_MARKET_RATIONALE.md) | 금융 맥락에서 왜 필요한가 |
| [03_PRD.md](03_PRD.md) | 제품 요구와 성공 기준은 무엇인가 |
| [04_MVP_SCOPE.md](04_MVP_SCOPE.md) | P0/P1/P2 범위는 어디까지인가 |
| [05_FINANCIAL_DOMAIN_MODEL.md](05_FINANCIAL_DOMAIN_MODEL.md) | 합성 금융 업무와 데이터는 무엇인가 |
| [06_FUNCTIONAL_SPEC.md](06_FUNCTIONAL_SPEC.md) | 각 기능의 실행 계약은 무엇인가 |
| [07_USER_FLOW_AND_STATE_MACHINE.md](07_USER_FLOW_AND_STATE_MACHINE.md) | 상태와 전이는 어떻게 움직이는가 |
| [08_SYSTEM_ARCHITECTURE.md](08_SYSTEM_ARCHITECTURE.md) | 시스템·신뢰 경계·배포 구조는 무엇인가 |
| [09_ERD_AND_DATA_DICTIONARY.md](09_ERD_AND_DATA_DICTIONARY.md) | 영속 모델과 생명주기는 무엇인가 |
| [10_API_SPECIFICATION.md](10_API_SPECIFICATION.md) | UI/Backend API 계약은 무엇인가 |
| [11_AGENT_RELEASE_MANIFEST_SPEC.md](11_AGENT_RELEASE_MANIFEST_SPEC.md) | Release 입력과 fingerprint 규칙은 무엇인가 |
| [12_SAFETY_CONTRACT_SPEC.md](12_SAFETY_CONTRACT_SPEC.md) | Policy-as-Code 문법과 의미는 무엇인가 |
| [13_THREAT_MODEL.md](13_THREAT_MODEL.md) | 자산·경계·공격자·영향은 무엇인가 |
| [14_ATTACK_CATALOG.md](14_ATTACK_CATALOG.md) | FA-01~06 공격 계약은 무엇인가 |
| [15_SECURITY_ORACLE_SPEC.md](15_SECURITY_ORACLE_SPEC.md) | 성공/실패를 코드로 어떻게 판정하는가 |
| [16_POLICY_GATEWAY_SPEC.md](16_POLICY_GATEWAY_SPEC.md) | 도구 호출을 어떤 순서로 허용/차단하는가 |
| [17_EXECUTION_TRACE_AND_AUDIT_SPEC.md](17_EXECUTION_TRACE_AND_AUDIT_SPEC.md) | 관찰 가능한 증거를 어떻게 남기는가 |
| [18_TEST_AND_EVALUATION_PLAN.md](18_TEST_AND_EVALUATION_PLAN.md) | Seed/Held-out/정상업무를 어떻게 실험하는가 |
| [19_METRICS_AND_RELEASE_GATE.md](19_METRICS_AND_RELEASE_GATE.md) | 측정식과 PASS/REVIEW/BLOCKED 조건은 무엇인가 |
| [20_UI_UX_SPEC.md](20_UI_UX_SPEC.md) | Release Detail 중심 UX는 어떻게 동작하는가 |
| [21_DEMO_SCRIPT.md](21_DEMO_SCRIPT.md) | 60초/3분/5분 시연을 어떻게 진행하는가 |
| [22_SECURITY_AND_PRIVACY_SPEC.md](22_SECURITY_AND_PRIVACY_SPEC.md) | 제품 자체 보안 요구는 무엇인가 |
| [23_DEPLOYMENT_AND_OPERATIONS_PLAN.md](23_DEPLOYMENT_AND_OPERATIONS_PLAN.md) | 로컬/대회 배포와 장애대응은 어떻게 하는가 |
| [24_DEVELOPMENT_PLAN.md](24_DEVELOPMENT_PLAN.md) | Vertical Slice 구현 순서는 무엇인가 |
| [25_TEST_CASE_MATRIX.md](25_TEST_CASE_MATRIX.md) | 구현 검증 케이스는 무엇인가 |
| [26_TRACEABILITY_MATRIX.md](26_TRACEABILITY_MATRIX.md) | 문제부터 Demo까지 어떻게 연결되는가 |
| [27_RISK_REGISTER.md](27_RISK_REGISTER.md) | 기술·일정·신뢰성 리스크는 무엇인가 |
| [28_COMPETITION_SUBMISSION_MAPPING.md](28_COMPETITION_SUBMISSION_MAPPING.md) | 제출 문서에 무엇을 옮기는가 |
| [29_REGULATORY_FRAMEWORK_CROSSWALK.md](29_REGULATORY_FRAMEWORK_CROSSWALK.md) | 공신력 있는 원칙과 기능은 어떻게 참고 매핑되는가 |

## 개발 시작 체크리스트

- `00`의 결정 및 P2 질문을 Product Owner와 Security Reviewer가 서명한다.
- OpenAPI는 `10`, DB migration은 `09`, Pydantic/TypeScript 타입은 `10`~`12`에서 생성한다.
- 첫 구현은 `24`의 Vertical Slice 1이며, 로그인·대시보드부터 시작하지 않는다.
- 모든 외부 전송 도구는 실제 인터넷 대신 Mock Exfiltration Collector만 가리킨다.
- LLM 판단을 Oracle, 정책 허용, Release Gate의 최종 판정에 사용하지 않는다.
- 문서 변경 시 `26` 추적성 행과 관련 테스트를 함께 갱신한다.

## 용어 규칙

- **Baseline**: Broad Service Account / Tool-level Permission Baseline. IAM/RBAC 전체가 불안전하다는 뜻이 아니다.
- **SEAL run**: 승인된 Safety Contract가 Policy Gateway에서 강제되는 시험.
- **Finding**: Deterministic Oracle이 실제 API 응답 또는 Sandbox side effect로 입증한 보안 위반.
- **Release Attestation**: FINSEC SEAL 내부 검증 증거 묶음. 공식 인증이 아니다.
- **Human-only**: Agent가 실행하지 않고 권한 있는 사람이 별도 절차로 수행하는 고영향 행동.

