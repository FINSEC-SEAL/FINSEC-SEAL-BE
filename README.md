# FINSEC SEAL Backend

금융 AI Agent가 업무 목적을 벗어나 고객정보·Tool·외부 시스템·고영향 금융 권한을 사용하는지 배포 전에 검증하는 **Agent Release Assurance Platform**의 백엔드 저장소입니다.

FINSEC SEAL은 합성 금융 Sandbox에서 공격을 실행하고, 금융 업무 문맥 기반 Safety Contract 적용 전후의 공격 및 정상업무를 재검증하여 내부 Release Decision(`PASS`, `REVIEW`, `BLOCKED`)과 증거를 생성합니다.

## 현재 상태

Role A(Platform / Data / Evidence)의 공통 Spring Boot 기반, PostgreSQL 저장 무결성,
Agent/Release/Manifest/Fingerprint API를 구현했습니다.
현재 코드 기준 Architecture는 [A Architecture Baseline](docs/A_ARCHITECTURE_BASELINE.md)이며,
기존 `docs/predev` 문서는 요구사항 참고자료로 사용합니다.

전체 요구사항, Architecture, ERD, API, Threat Model, Policy Gateway, Security Oracle, 테스트 및 개발 계획은 아래 문서를 기준으로 합니다.

- [개발 전 설계 문서 전체 보기](docs/predev/README.md)
- [MVP 범위](docs/predev/04_MVP_SCOPE.md)
- [System Architecture](docs/predev/08_SYSTEM_ARCHITECTURE.md)
- [API Specification](docs/predev/10_API_SPECIFICATION.md)
- [Development Plan](docs/predev/24_DEVELOPMENT_PLAN.md)

## MVP Use Case

**대출서류 완전성 검토 Agent** 한 가지 업무를 대상으로 합니다. 이 Agent는 제출서류의 누락 여부를 검토하지만 대출 승인·거절, 금리·한도 결정 또는 금융거래를 수행하지 않습니다.

대표 검증 흐름은 다음과 같습니다.

```text
Baseline Attack
→ Synthetic Side Effect
→ Deterministic Oracle Finding
→ Safety Contract Approval
→ Same Attack Replay
→ Held-out Attack + Normal Regression
→ Internal Release Decision
```

## Runtime Stack

- Core backend: Java 21, Spring Boot 4.1.1, Gradle 9.7.1
- AI service: Python/FastAPI stateless service (별도 `FINSEC-SEAL-AI` 저장소)
- Database: PostgreSQL 17.11
- Policy: Custom deterministic evaluator
- Progress streaming: Server-Sent Events
- LLM: Provider abstraction with an OpenAI-compatible adapter

## Local verification

Docker Desktop을 실행한 뒤 다음 명령을 사용합니다.

```bash
./gradlew clean test
SPRING_PROFILES_ACTIVE=local ./gradlew bootRun
```

Docker Compose 실행 시에는 `.env.example`을 참고해 `.env`를 만들고 32-byte 암호화 키를 설정합니다.

```bash
openssl rand -base64 32
docker compose up --build
```

- Health: `GET http://localhost:8080/actuator/health`
- Role A 구현/사용법: [docs/A_ROLE_IMPLEMENTATION.md](docs/A_ROLE_IMPLEMENTATION.md)
- 선임 검증 기록: [docs/A_SENIOR_REVIEW_LOG.md](docs/A_SENIOR_REVIEW_LOG.md)

## Disclaimer

FINSEC SEAL의 결과는 합성 환경에서 수행한 내부 보안검증 결과입니다. 금융당국·금융보안원 또는 기타 금융보안 기관의 공식 인증이나 규제 준수 판정을 의미하지 않습니다.

> This is an internal FINSEC SEAL MVP security assessment and not an official certification by any regulatory or financial-security authority.
