# Role C: 저장된 호출에 결합한 Gateway 검토자

`StoredGatewayReviewerContextSource`는 서버에 저장된 한 `TOOL_PROPOSED`의 검토자 권한을 기존 A·B reader로 조회하는 C 구현이다. 요청의 actor나 key를 그대로 신뢰해 권한을 만들지 않는다. A의 자격 증명·Run 등록·폐기·권한 stamp, B의 실행·sandbox scope, D의 판정과 지표는 변경하지 않는다.

## 활성화와 배포 조건

기본 설정은 Gateway 비활성 상태를 유지한다. 이 provider를 등록하려면 아래 **두 속성 모두** 명시적으로 `true`여야 한다.

- `finsec.policy.gateway.enabled`
- `finsec.policy.gateway.reviewer.stored.enabled`

등록되는 qualifier는 `loanReviewGatewayReviewerContext`다. 저장소의 기본 설정을 바꾸거나 fallback 검토자를 추가하지 않는다. 원격 Gateway 설정인 `policy.gateway.enabled` 또는 `policy.gateway.c.enabled`와 로컬 C Gateway를 동시에 활성화하면 기존 configuration이 거절한다.

주입되는 DataSource는 Hikari여야 하며 `connectionTimeout`은 양수이고 **5,000ms 미만**이어야 한다. Hikari 기본 30,000ms 설정은 이 provider의 조건을 충족하지 않는다. resolve 때 pool 설정을 다시 확인하므로 실행 중 한도를 바꿔도 권한을 반환하지 않는다. 단순히 위 속성을 켜는 것은 배포 준비 완료를 의미하지 않는다.

Gateway가 요구하는 별도 `GatewayRuntimeObservations` 구현도 필요하다. `StoredGatewayPreCallScopeSource`는 B의 저장된 pre-call scope reader이고, before/call completion/output 및 완전한 state witness를 제공하는 전체 observations bean이 아니다. 이 C provider는 그 bean이나 실제 B 실행 경로를 구현·대체하지 않는다. 현재 변경만으로 전체 ENFORCE 활성화, 실제 공격 차단 또는 시스템 완성을 주장할 수 없다.

## 권한·snapshot·기한

`InvocationKey`의 run, caseRun, trace, toolCall, requestDigest 전체가 저장된 제안과 결합돼야 한다. A reader는 현재 workspace/actor/role의 authority stamp, grant 만료, session 폐기 기록과 실행 상태를 확인한다. C는 기존 `SafetyContractLifecyclePolicy.requireReviewerContext`를 재사용해 검토자 도메인과 opaque session digest를 검증하고, B 반환값의 같은 key·namespace·서버 run/case/trace를 확인한다.

각 호출은 가져온 **하나의 새 연결**에 fresh read-only `REPEATABLE_READ` transaction을 연다. A와 B는 그 동일한 Spring-bound 연결을 사용하고 성공 경로도 rollback한다. caller에 이미 transaction/resource/synchronization이 있으면 가져오기 전에 거절하며 그 caller 상태를 변경하지 않는다.

전달받는 remaining budget은 양수이며 최대 5초다. pool acquisition timeout 또는 최소 reader 1초 이하의 budget은 가져오기 전에 거절한다. A·B statement가 남은 1초 미만이면 진행하지 않는다. 연결 가져오기, transaction setup, 두 reader, rollback/cleanup와 최종 반환에 같은 monotonic deadline을 사용하며, B가 받는 budget은 A 이후의 감소한 remaining 값이다. public 반환 직전에는 원래 grant 만료도 다시 확인한다.

최대 두 deadline lease만 동시에 허용한다. deadline caller가 반환했거나 Hikari active connection이 0이어도 백그라운드 정리가 끝났다고 보지 않는다. worker와 watchdog이 모두 정리된 후에만 슬롯을 돌려준다. 정상 조회도 watchdog의 늦은 abort가 다른 borrower를 건드리지 않도록 가져온 연결을 폐기하므로, 배포 시 연결 재생성 비용을 고려해야 한다. 전파되거나 provider가 감지한 중단·SQL·설정·rollback/cleanup·폐기 실패는 resolution을 반환하지 않으며 owner/driver의 private cause를 public Gateway 오류에 붙이지 않는다.

Spring은 성공한 rollback 뒤 auto-commit·isolation·read-only 복원 예외를 내부에서 흡수할 수 있다. 그 복원 실패만 발생했다면 정확한 권한 조회가 성공하고 해당 연결의 필수 폐기 및 최종 기한·권한 만료 검사를 통과한 resolution은 반환될 수 있다. 연결 폐기는 같은 물리 연결을 재대여하지 않게 하는 조치이며, caller 반환 전에 비동기 물리 close까지 완료됐다는 보장은 아니다. 모든 복원 오류의 거절이나 탐지를 주장하지 않는다.

## 내부 운영 진단

기존 Micrometer에 `finsec.policy.gateway.reviewer.failure.events` FunctionCounter를 등록한다. provider의 `reason` tag는 `deadline_capacity`, `interrupted`, `caller_timeout`, `execution_failure`, `resolution_failure`, `retirement_failure`, `abort_failure`의 고정 범주뿐이다. actor·session·호출 key·SQL·예외·저장 context를 이름이나 tag에 넣지 않는다.

counter와 observer 등록은 source class 시작 때만 수행한다. resolve·worker·watchdog의 실패 경로는 미리 생성한 AtomicLong을 증가시키며 registry 조회·등록, logging, exporter I/O를 호출하지 않는다. 각 등록의 RuntimeException은 진단 비가용으로 격리하고 권한·공개 오류를 바꾸지 않으며 Error는 흡수하지 않는다. exporter 또는 등록이 비가용이면 운영 진단이 보이지 않을 수 있다. 기본 web 노출은 health/info이며 이 변경은 metrics endpoint나 exporter 설정을 추가하지 않는다.

계수는 관찰된 운영 실패 **event**다. worker와 watchdog이 한 요청의 다른 실패를 각각 관찰할 수 있으므로 고유 요청 수, 모든 거절의 완전한 집계, 성공한 보안 차단 또는 D의 업무 지표로 해석하지 않는다. Spring이 흡수한 복원 예외의 탐지도 이 counter로 보장하지 않는다.

## 보장 범위

session digest는 **Run 등록 시** 서명된 자격 증명과 CSRF가 확인됐다는 A의 저장된 근거다. 현재 브라우저 세션이나 새로운 CSRF 요청을 조회한 결과가 아니다. `ReviewerContext`의 확인 값도 이 등록 근거에 한정된다. 원래 만료를 cleanup와 최종 반환까지 확인하지만, 반환 후 계속 유효하다고 보장하지 않는다.

폐기·scope 조회는 같은 repeatable-read snapshot에서 수행된다. 그 snapshot이 시작된 뒤 동시 기록된 폐기의 즉시 반영을 보장하지 않는다. A의 grant/stamp는 애플리케이션 등록 근거이며 DB 관리자에 대한 별도 암호학적 증명도 아니다. 전체 runtime 관찰·사후 output redaction·상태 변화 증명은 별도 B/C Gateway 기능의 근거가 필요하다.

권한 조합 실패는 Gateway의 `AUTHENTICATION_REQUIRED` 또는 기한 경계의 `POLICY_EVALUATION_TIMEOUT` 같은 운영 실패다. 이를 성공한 보안 차단으로 집계하지 않는다. 검토자 확인 전에 adapter, 정책 출처·catalog, runtime observations, 이벤트·mutation·redaction 등 후속 의존성이 호출돼서는 안 된다.

## 검증과 명세 연결

C 소유 source와 두 source test, 이 문서만 변경한다. 구현은 C-GW-004/005/007/008 및 C-BND-001의 호출별 권한·기한·실패 경계에 해당한다. 연결된 TC-GW-001~013, TC-SBX-002/004, TC-OR-007, TC-MET-002, TC-CON-004~006 전체 시스템 기준의 완료를 이 provider 하나의 시험으로 대체하지 않는다. TC-GATE는 D의 Release Gate이며 C Gateway 기능 이름과 혼동하지 않는다.

source 시험은 실제 PostgreSQL의 A·B reader를 사용해 물리 연결과 Spring-bound proxy, backend PID, autocommit false/read-only/repeatable-read, 감소한 budget, 실제 lock·setup·rollback·abort·lease 회복을 관찰한다. 짧은 grant가 rollback 중 만료되는 시험과 동일 조건의 정상 grant 대조가 있고, 기존 결함 source에 동일 시험을 실행한 예상 실패 근거도 별도로 보존한다. 세 복원 setter의 실패는 실제 rollback 성공 뒤에만 주입하며, 실제 반환 권한·정확한 borrowed lease 폐기·물리 close 완료·정리 후 새 연결의 단 한 번 정상 조회와 16-table digest를 확인한다. 운영 진단은 고정 tag, 실패 event delta 및 등록 비가용 시 권한·공개 실패·저장 근거 보존을 검증하고, 시험 registry만 제거·닫는다.

BASELINE와 SEAL_REPLAY 실패 시험은 실제 Agent/Release 생성·분석과 서명된 Run 등록을 사용한다. Replay는 정상 도메인 TESTING→REMEDIATION 전이와 실제 contract create/validate/approve, 새 ETag를 사용하며 same-release APPROVED 제약을 유지한다. 저장된 mode와 caller mode를 확인하고 각 정상 key의 source 성공 대조 후 wrong digest, 폐기 grant, 실제 SEALED namespace, PostgreSQL setup 기한 실패를 실제 source와 Gateway에 전달한다. 이 contract 준비는 시험 fixture이며 이전 remediation 실행이나 Replay 효력의 증거가 아니다.

B 반환값의 의도적인 null/잘못된 key·context·namespace identity는 실제 reader의 local spy에만 주입한다. 이는 조합 경계의 fault 시험이며 실제 B SQL이 그런 값을 생성한다는 주장이 아니다. typed ACTIVE namespace 생성 규칙을 우회하지 않고 B의 업무 규칙을 중복 구현하지 않는다.

무변경 비교는 정리가 끝난 뒤 고정 allowlist의 16개 테이블 전체 행과 순서를 hash한다: Run, CaseRun, reviewer grant/revocation, sandbox namespace/customer/loan case/document/policy/note/decision/exfil, execution event/counter, tool idempotency record, audit record. fixture 변경·폐기·SEALED 처리는 before snapshot 이전에 완료한다. 이벤트 `RUN_STARTED`/`TOOL_PROPOSED`와 sequence 2를 유지하고 adapter 0회, 모든 후속 mock 무호출, cause 없는 운영 실패와 `successfulSecurityBlock=false`를 확인한다. 이는 해당 실패 경계의 근거이며 다른 모든 테이블이나 실제 실행 전체의 불변성 증명은 아니다.

새 검증 명령은 `./gradlew test --rerun-tasks --no-build-cache --no-daemon`이며 source 범위는 `--tests '*StoredGatewayReviewerContextSource*Test'`로 선택한다. 실제 owner·Gateway·HTTP 권한·실행 수락 회귀와 필수 전체 BE/AI 검증, 정확한 최종 파일의 Supervisor checkpoint 및 같은 run의 post를 모두 통과한 뒤에만 전달한다. focused PASS만으로 최종 전달 완료를 표시하지 않는다.
