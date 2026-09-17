# A 생성 작업 설계 결정 — 2026-09-08

기준 dev: `1c9bb84`. 이 문서는 A가 1차 확정한 접수·저장 계약이다. C의 기존 생성·검증 규칙과 B transport를 호출하며 그 규칙을 복제하지 않는다. 구체적인 연결 방법은 [C 인계 문서](A_TO_C_GENERATION_HANDOFF.md)를 따른다.

## 결정

1. 원 명세의 `POST /api/v1/releases/{id}/contracts:generate`, `POST /api/v1/findings/{id}/patch-proposals`를 A가 소유한다. 결과를 기다리는 200 응답 대신 DB 작업을 commit한 후 202와 Location을 반환한다. 상태 조회 확장 경로는 `GET /api/v1/operations/{id}`다.
2. 작업 상태는 QUEUED/RUNNING/SUCCEEDED/FAILED/RECOVERY_REQUIRED, 생성 판단은 VALID/WARN/INVALID/PROPOSED/NO_CHANGE_NEEDED로 분리한다. INVALID는 검증이 완료된 SUCCEEDED 결과이며 새 후보를 저장하지 않는다. SUCCEEDED는 승인이나 안전성 PASS가 아니다.
3. 인증 → provider 가용성 확인 → 공통 멱등성 → workspace/출처 확인·ID 예약·작업 저장 순서다. provider 비활성화는 멱등키를 예약하기 전 503이다. 인증된 workspace를 공통 멱등성 scope에 사용한다.
4. workspace의 활성 작업은 최대 20개, 같은 Release에는 최대 1개다. 접수 transaction이 workspace/Release 잠금으로 동시 요청을 직렬화하고 DB partial unique index가 마지막 중복을 차단한다. polling worker는 프로세스당1개이며 별도 thread에서 실행해 공통 scheduler/lease heartbeat를 막지 않는다.
5. 예약은 `operationId`, 후보 `versionId` UUIDv7, contractKey, 정수 version을 포함한다. 초기 key는 지원 금융 템플릿의 `loan-review-default`, version은 마지막 저장 version+1이다. 패치는 최신 base version만 허용한다. 예약 중 직접 후보 저장은409다. 실패한 예약의 정수 version은 재사용할 수 있지만 UUID/claim token은 재사용하지 않는다.
6. QUEUED→RUNNING은 짧은 transaction의 `FOR UPDATE SKIP LOCKED`와 claim token으로 획득한다. C 호출은 transaction/synchronization 밖이다. source 접근 transaction은 C가 관리한다. 결과 저장과 작업 성공, 모델 메타데이터, 감사는 하나의 별도 transaction이다.
7. 접수·호출 직전·생성 결과·저장 시점의 SourceBinding/analyzedAt을 비교한다. 패치는 Finding facts, Run/Case/Oracle, base state/policy/resource hash까지 비교한다. 달라지면 FAILED로 종료하며 결과를 저장하지 않는다. source의 원문 evidence는 작업 테이블에 넣지 않는다.
8. Worker 권한은 인증된 actor/workspace/session의 서버 측 snapshot과 30분 작업 권한으로 보존한다. 쿠키·CSRF token·API key를 저장하지 않는다. 설정 키/actor/workspace를 변경하면 authority stamp가 달라져 실행·저장이 거절된다. 작업 권한은 접수 시 위임되며 브라우저 쿠키의 남은 유효기간과 별개다.
9. 실행 lease 기본 180초(30..1800) 만료는 RECOVERY_REQUIRED다. 이미 외부 호출했는지 불명확하므로 자동 재실행하지 않는다. 늦은 결과는 status/token/lease 검사로 차단한다. B의 요청 내부 retry 외에 A/C는 추가 모델 retry를 하지 않는다.
10. 접수 idempotency record UUID/digest를 작업에 남긴다. 응답 캐시 commit 전에 서버가 중단되면 기존 멱등성 복구 절차를 사용하며 작업 연결부터 확인한다. 캐시의202는 최초 접수 응답이므로 항상 상태 조회로 현재 결과를 확인한다.
11. V15에서 작업 입력·terminal 상태·생성 기록을 불변으로 봉인한다. 성공에는 생성 기록이 필요하며 예약한 UUID와 저장 version/proposal의 결합을 검사한다. migration은 기존 V1~V14를 수정하지 않는다.

## 제외 범위

새 메시지 브로커, 공개 guest workspace 발급, 모든 팀의 Replay orchestration, 모델 provider 구현, 자동 승인, 자동 모델 재시도는 추가하지 않는다. 현재 B 기본 provider의 patch envelope 지원과 실제 외부 모델 실행은 별도 확인 대상이다. 상태를 강제로 RUNNING/QUEUED로 되돌리는 공개 API도 제공하지 않는다.
