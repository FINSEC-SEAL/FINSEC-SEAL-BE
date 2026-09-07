# A 계약 API 인수인계

## 원 명세 대응

기준은 `docs/predev/10_API_SPECIFICATION.md`다. A 패키지 소유권은 URL 접두사를 결정하지 않는다.
기존 `/platform/contracts`만 제공하던 구현을 보완해 아래 원 명세 경로를 제공한다.
공통 접두사는 `/api/v1`, 응답은 프로젝트 공통 `{data,traceId,timestamp}` envelope다.

| Method / 경로 | 요청 | data 응답 |
|---|---|---|
| GET `/contract-versions/{id}` | version UUID | ContractVersion: 기존 Version 필드 + `contractId`(DB UUID), `diff` |
| GET `/contracts/{id}/versions` | **contract UUID**, `limit=1..100`(기본25), `cursor?` | `{items,nextCursor}`; version 오름차순 |
| POST `/contract-versions/{id}:validate` | `{}`, strong If-Match | ValidationResult: C의 `status,issues` + `versionId,state,policyHash,resourceHash,validationProof` |
| POST `/contract-versions/{id}:approve` | `{comment,patchProposalId?}`, strong If-Match | ApprovedVersion: ContractVersion과 같은 형태, state=APPROVED |

`contractId`(DB UUID), `contractKey`(정책 JSON의 contractId 문자열), version `id`는 서로 다른 값이다.
목록 주소에 Release ID나 version ID를 넣지 않는다. `nextCursor=null`이면 마지막 페이지다.
`diff`는 직전 서버 소유 버전과 비교한 최상위 정책 필드별 `{path,before,after}` 배열이다.
첫 버전의 before는 null이며 policy는 canonical 공개 정책이다. 원문 프롬프트를 포함하지 않는다.

추가 A 인터페이스:

| Method / 경로 | 용도 |
|---|---|
| POST `/platform/contracts` | `{releaseId,policy}`로 **이미 생성된** 후보 저장, 201 Version |
| GET `/platform/contracts?releaseId=…` | Release별 서버 소유 후보 조회(기존 응답 유지) |
| POST `/contract-versions/{id}:reject` | `{comment}` + If-Match, 거절 |
| GET `/contract-versions/{id}/approved?releaseId=…` | 현재 승인본과 Agent artifact / Release fingerprint |
| GET `/platform/patch-sources/{findingId}` | 적격 Finding facts와 digest 검증된 Oracle evidence |
| GET `/reviewer-session` | 아래 검토자 자격을 세션으로 교환하거나 현재 세션의 CSRF 토큰 조회 |

이전 `/platform/contracts/{id}` 및 `:validate`, `:approve`, `:reject`, `/approved` 경로는 기존 호출자 호환용이다.
새 호출자는 원 명세 경로를 사용한다. 두 경로 모두 같은 저장 로직·권한·If-Match·감사를 사용한다.
기존 경로의 validate는 Version 응답을 유지하며, 원 명세 경로의 validate는 ValidationResult를 반환한다.

## 인증 및 CSRF

로그인 UI는 추가하지 않는다. 검토자 권한은 서버가 설정한 자격에서만 발급된다. 익명 체험이나 X-Actor-Id만으로 승인을 허용하지 않는다.
기본값은 비활성화(403)다. 서버 환경 변수 및 Compose 전달 항목:

```text
FINSEC_CONTRACT_ACCESS_KEY=<최소 32바이트의 무작위 비밀값>
FINSEC_CONTRACT_ACCESS_ACTOR=<검토자 식별자>
FINSEC_CONTRACT_ACCESS_WORKSPACE=<workspace UUID>
```

개발 workspace는 `0198f1e2-0000-7000-8000-000000000001`이다. 키는 git·프론트 bundle·URL·localStorage에 넣지 않는다.

브라우저 세션 절차:

1. 신뢰된 검토자가 `GET /api/v1/reviewer-session`에 `X-Contract-Reviewer-Key`를 보낸다.
2. 서버가 30분 유효한 `__Host-FINSEC_REVIEWER` 쿠키(`HttpOnly; Secure; SameSite=Lax; Path=/`)와 `{csrfToken,expiresAt,actorId,workspaceId,role}`를 반환한다. 응답은 `Cache-Control: no-store`다.
3. 이후 요청은 쿠키를 보내며, POST에는 `X-CSRF-Token`을 추가한다. 브라우저 연결에는 HTTPS와 허용 Origin 설정이 필요하다. 쿠키를 쓰는 fetch는 `credentials: 'include'`를 사용한다.
4. 새로고침 후 같은 GET을 세션 쿠키로 호출하면 CSRF 토큰을 다시 받을 수 있다. 만료 시 검토자 자격으로 재발급한다.

세션은 서명된 서버 Actor/workspace/만료 시각을 검증한다. 키 또는 Actor/workspace 설정을 변경하면 기존 세션은 무효가 된다.
서버 간 호출 및 로컬 CLI는 Cookie 없이 `X-Contract-Reviewer-Key`를 직접 사용할 수도 있다.
Cookie가 있는 요청에서는 키를 함께 보내도 CSRF 검사를 우회할 수 없다. 모든 원 명세/호환 경로에서 인증이 멱등성 처리보다 먼저 실행된다.
X-Actor-Id를 보낸다면 서버 Actor와 같아야 한다. role/workspace/authenticated는 본문에서 받지 않는다.

이 세션은 **설정된 workspace의 검토자 자격**을 위한 것이다. 공개 방문자별 demo workspace 자동 생성·guest session 발급 전체를 구현했다는 의미가 아니다.
개인별 SSO나 여러 검토자 계정 관리도 포함하지 않는다. 그런 공통 Demo 기능은 이 변경의 완료 범위와 구분한다.

## 상태·멱등성·응답 검증

모든 POST에 Idempotency-Key가 필요하다. If-Match는 `"<resourceHash>"` 형식이며 policyHash를 대신 쓰지 않는다.
검증 후 resourceHash가 바뀌므로 **검증 응답의** resourceHash로 승인한다. 공통 멱등성 재응답은 ETag 헤더가 아닌 본문의 resourceHash를 기준으로 한다.
원 명세 validate body는 `{}`만 허용하고, approve는 comment와 선택적 patchProposalId 이외 필드를 거절한다.

- INVALID 검증은 CANDIDATE 상태를 유지하고 C의 결과를 반환한다.
- 오래된 If-Match/base 또는 활성 Run은 409다. 후보 생성은 분석된 Release에 허용한다.
- 승인·Release 적용은 기존 DB 계약의 REMEDIATION → VERIFYING 또는 PASS/REVIEW/BLOCKED → NEEDS_REVALIDATION에서만 가능하다.
- 승인·거절본과 검토 기록은 불변이다. 이전 판정은 무효화 기록을 남기며 과거 Attestation 원문과 hash를 유지한다.
- 현재 승인본 조회는 저장 hash, 검증 proof, review, Release/version/workspace 결합과 artifact를 확인한다. 조회 시점 snapshot이므로 Gateway는 실행의 고정 fingerprint와 다시 대조해야 한다.

## 패치 연결

`ContractPersistenceService.storePatch(findingId,baseVersionId,ProposedPatch,reviewer)`는 B/C가 생성한 후보를 받는 **내부 저장 인터페이스**다.
A가 DB에서 출처·base·catalog를 다시 읽고 C의 `SafetyContractPatchProposalPolicy`를 호출한다. C가 PROPOSED로 인정한 결과만 후보·proposal·검증 증거와 함께 원자적으로 저장한다.
반환값은 `{patchProposalId,candidate}`다. 이 메서드는 모델을 호출하지 않는다.

승인 body의 patchProposalId는 존재 여부, 동일 Release, PROPOSED 상태, 해당 candidate ID, C의 재검증 결과와 정책 hash를 확인한다.
성공 시 불변 patch_approvals와 계약 승인·Release 반영·감사를 같은 transaction에 저장한다.
패치 후보에 연결된 patchProposalId를 생략하거나 다른 ID를 보내면 409이며, 임의 proposal ID를 무시한 채 일반 승인하지 않는다.

패치 출처는 OPEN/TRIAGED Finding → ATTACK_SUCCESS Oracle → 완료된 BASELINE/SEAL_REPLAY Run의 SEED/MUTATION만 허용한다.
증거 본문을 읽기 전에 workspace·suite·Release와 부모 계보를 확인한다. HELD_OUT·숨김·숨김 원본의 파생·외부 workspace·순환 계보는 제외한다.
통과한 Oracle evidence도 canonical digest를 검사한다. 불허 출처와 미존재 ID는 모두 404다.

## 별도 팀 연결 범위

`POST /releases/{id}/contracts:generate`와 `POST /findings/{id}/patch-proposals`의 실제 AI 생성·비동기 작업 접수는 B/C 생성 연결 범위다.
A의 후보 저장이나 storePatch를 이 생성 API가 완료된 것으로 간주하지 않는다. 현재 생성 API의 202 성공을 합성하지 않는다.
C 화면·Gateway의 API 사용과 B의 실행 문맥·도구 응답 연결 및 전체 Replay는 별도 통합 작업이다.

## Migration / 검증

V14는 서버 생성 버전의 hash·검토 metadata를 보존한다. 기존 migration checksum은 변경하지 않았다.
무결성 metadata가 없는 legacy 계약을 현재 승인 권한으로 자동 승격하지 않으며 새 API 이력 대상에서도 제외한다.

```sh
./gradlew test --tests 'com.finsecseal.platform.contract.*'
FINSEC_AI_LIVE_E2E=false ./gradlew test bootJar
```

원 명세 주소를 직접 호출하는 HTTP 테스트로 상세·계약별 페이지·ValidationResult·승인·오래된 hash·알 수 없는 필드·proposal ID를 검증한다.
추가로 세션 발급, 쿠키 속성, 만료·서명·workspace, CSRF 실패 전 멱등성 차단, 패치 승인 연결, 동시 승인과 보고서 보존을 검증한다.

검증 기록(2026-09-07): 전체 1,301개 중 1,300개 통과, 외부 AI 호출 1개 제외. 이후 Finding 잠금 및 패치 증거 변조 검사 보완 후 계약 테스트 16개와 bootJar 재검증 통과.
