# A 계약 저장·승인·패치 출처 연결

## 구현 범위

`platform.contract`는 A 소유의 영속화·무결성·인증 경계다. C의 `SafetyContractLifecyclePolicy`와 canonicalizer를 그대로 호출하며 승인 규칙을 재구현하지 않는다. B의 모델 호출·Tool 실행, C Gateway, D Oracle·판정 코드는 수정하지 않는다.

- 후보의 canonical 정책과 hash, 서버에서 읽은 base policy hash, resource hash 저장.
- C 검증 proof 저장과 CANDIDATE → VALIDATED 전이. INVALID 후보는 CANDIDATE로 유지하며 결과를 반환.
- 최신 Release를 먼저 잠근 후 strong If-Match를 확인하고 C 승인/거절 판단을 호출.
- 승인 proof·검토자·의견·불변 승인본과 감사 기록을 한 transaction에 저장.
- 기존 `ReleaseService.applySafetyContractHash`로 Release fingerprint를 변경. 기존 확정 판정은 invalidation을 남기고 과거 Attestation 원문/hash를 보존.
- 현재 Release policy hash와 일치하는 승인본만 Gateway용 조회에 반환. 과거 승인본은 일반 버전 조회에 보존.
- 실제 Finding → Oracle → CaseRun → Run → Case/Suite의 출처를 확인한 전용 patch source 조회.

## 인증: MVP 로그인 없음 유지

로그인 UI·세션 로그인은 추가하지 않는다. 신뢰 경계가 필요한 새 API는 서버 관리자가 프로비저닝한 **한 workspace의 검토자 API 자격**을 사용한다. 기본값에서는 자격이 없어 403으로 닫힌다. 익명 체험 화면을 실제 승인으로 승격시키지 않는다.

서버 환경 변수:

```text
FINSEC_CONTRACT_ACCESS_KEY=<최소 32바이트의 무작위 비밀값>
FINSEC_CONTRACT_ACCESS_ACTOR=<감사에 남길 검토자 식별자>
FINSEC_CONTRACT_ACCESS_WORKSPACE=<검토자가 접근할 workspace UUID>
```

Docker Compose도 이 세 환경 변수를 backend 컨테이너에 전달한다. 브라우저 요청의 `credentials`는 `omit`을 사용하고, 필요한 Origin을 `FINSEC_CORS_ALLOWED_ORIGINS`에 등록한다. 사전 요청(OPTIONS)은 CORS 검사를 받으며 실제 데이터 요청의 인증을 대신하지 않는다.

현재 개발 workspace ID는 `0198f1e2-0000-7000-8000-000000000001`이다. 키는 서버 운영자만 배포하며 프론트 bundle·git·공유 문서에 넣지 않는다. 이 단계는 개인별 로그인/SSO가 아니므로 여러 사람에게 같은 키를 공유하면 사람별 신원 구분을 제공하지 않는다. 배포 시 HTTPS를 사용한다.

요청은 `X-Contract-Reviewer-Key`로 인증한다. `X-Actor-Id`를 생략하면 서버 설정 Actor를 적용하며, 다른 Actor를 보내면 거절한다. role/authenticated/csrfVerified/workspace는 요청 본문에서 받지 않는다. Cookie 요청을 거절하고 비밀 custom header를 검증하여 C의 신뢰된 ReviewerContext를 만든다. 이 필터는 멱등성 예약·재응답보다 먼저 실행된다. 따라서 실패 요청은 예약을 만들지 않고, 자격을 잃은 요청도 과거 승인 응답을 재사용할 수 없다.

## API 계약

공통 접두사: `/api/v1/platform`

| Method | 경로 | 입력 / 동작 |
|---|---|---|
| POST | `/contracts` | `{releaseId, policy}` 후보 생성. policy.contractId와 version은 C schema 기준이며 같은 계약에서 순차 버전만 허용 |
| GET | `/contracts?releaseId=…` | A 무결성 메타데이터가 있는 버전 목록 |
| GET | `/contracts/{versionId}` | 버전·정책·hash·검증 proof·검토 기록, ETag 반환 |
| POST | `/contracts/{versionId}:validate` | 최신 resource hash의 strong If-Match, C 검증과 proof 저장 |
| POST | `/contracts/{versionId}:approve` | strong If-Match와 `{comment}` |
| POST | `/contracts/{versionId}:reject` | strong If-Match와 `{comment}` |
| GET | `/contracts/{versionId}/approved?releaseId=…` | 현재 승인된 정책 + Agent artifact / Release fingerprint |
| GET | `/patch-sources/{findingId}` | 적격 출처 facts와 digest 검증된 Oracle evidence만 반환 |

표의 `/contracts`는 공통 접두사 `/api/v1/platform` 아래다. 모든 POST에는 기존 `Idempotency-Key`가 필요하다. 응답은 기존 `{data,traceId,timestamp}` envelope다. 버전 응답 `resourceHash`를 큰따옴표로 감싸 If-Match로 전송한다. 재시도 시 응답 본문의 resourceHash가 기준이며 공통 idempotency middleware가 ETag 헤더까지 재생한다고 가정하지 않는다. `policyHash`를 If-Match로 사용하지 않는다.

예: `If-Match: "sha256:..."`

검증 뒤 resourceHash가 바뀌므로 승인에는 **검증 응답의** resourceHash를 사용한다. 상태 충돌/오래된 base/활성 Run은 409, 권한 오류는 403, 적격 출처 없음은 404, C 검증·승인 조건 위반은 422 또는 해당 상태 오류다. 실제 승인에는 C의 WARN 확인을 포함한 검토 의견이 필요하다.

## Release 상태와 실행 연결

후보 생성은 분석된 Release에 허용한다. 실제 승인·정책 적용은 기존 DB 계약에 따라 **REMEDIATION → VERIFYING**, 또는 **PASS/REVIEW/BLOCKED → NEEDS_REVALIDATION**에서만 수행한다. 진행 중/대기 중 Run이 있으면 검증·승인을 거절한다. A가 없는 시험 결과나 보완 상태를 만들어내지 않는다. B/D 실행 소유자는 실제 baseline과 위험 결과를 근거로 적절한 Release 상태를 전달해야 한다.

B/C는 HTTP 승인본 조회 또는 `ContractPersistenceService.approved`를 재사용할 수 있다. 반환 snapshot은 조회 시점의 현재 승인본이며 장기 캐시 허가가 아니다. 실제 Gateway는 Run의 고정 version/fingerprint와 조회 snapshot을 대조하고 실행 시점까지의 변경을 통제해야 한다. 이 구현은 도구를 호출하거나 ENFORCE 완료를 주장하지 않는다.

## 패치용 Finding 출처

`PatchSourceService.find`는 C의 `FindingSourceFacts` 타입을 그대로 반환한다. 요청자가 partition/hidden/evidenceDigest를 지정하지 못한다.

1. 증거 본문을 읽기 전에 workspace/release/suite/run/case 연결을 조회.
2. OPEN/TRIAGED Finding, ATTACK_SUCCESS Oracle, 완료된 BASELINE/SEAL_REPLAY Run, SEED/MUTATION 및 hidden=false만 허용.
3. 부모 seed 계보까지 조사하여 HELD_OUT/숨김/다른 workspace 계보와 순환 계보를 거절.
4. 통과한 경우에만 Oracle evidence를 읽고 canonical digest를 검증.

관련 Finding 목록, 암호화된 공격 payload, 자유로운 상세 조회 결과는 전달하지 않는다. 불허 출처와 없는 ID는 같은 404 응답이다. 이는 C가 이미 정의한 적격성 규칙을 저장 조회에서 강제한 것이며 D의 Finding 판단을 변경하지 않는다.

## Migration / 검증

V14는 기존 계약 버전을 다시 승인된 것으로 간주하지 않고, 새 서버 생성 버전에 무결성 메타데이터를 추가한다. 기존 SQL migration은 변경하지 않았다. 승인·거절 후 review metadata도 변경할 수 없다.

```sh
./gradlew test --tests 'com.finsecseal.platform.contract.*'
FINSEC_AI_LIVE_E2E=false ./gradlew test
```

새 PostgreSQL/HTTP 테스트는 계약 생명주기, If-Match, 동시 승인, 잘못된 reviewer와 workspace, idempotency, 변조 탐지, 승인본 불변성, 이전 보고서 보존, 패치 출처·숨김 계보 필터를 검증한다. 실제 LLM/Gateway 실행은 포함하지 않는다.

C/B 연결이 남는 항목: 후보 생성 호출, 정책 후보 UI의 실 API 사용, Gateway용 실행 문맥·응답 provenance, 실제 Replay. A가 후보나 실행 결과를 합성해 이 경계를 대신하지 않는다.

검증 기록(2026-09-07): 전체 1,295개 중 1,294개 통과, 실제 외부 AI 호출 1개는 비활성화되어 건너뜀. 이후 CORS·설정 전달 보완을 포함한 A 통합 테스트 11개 및 bootJar 빌드 통과.
