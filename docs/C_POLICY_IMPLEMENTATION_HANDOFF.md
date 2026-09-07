# C 정책 판단 구현 및 통합 인계

이 문서는 C 판단 코어의 구현 범위와 남은 연결 작업을 기록한다. 전체 Role C 또는 ENFORCE/Generation/Replay의 실제 실행 완료를 뜻하지 않는다. 책임 기준은 [A Architecture Baseline](A_ARCHITECTURE_BASELINE.md)과 [4인 역할분담](../FINSEC_SEAL_4인_역할분담.md), 판단 규칙은 [Safety Contract](predev/12_SAFETY_CONTRACT_SPEC.md)와 [Policy Gateway](predev/16_POLICY_GATEWAY_SPEC.md)를 따른다.

## 구현된 판단

| 요구사항 | 구현과 증거 | 아직 증명하지 않는 동작 |
|---|---|---|
| C-SC-001/002/003 | closed schema, canonical policy/hash, 정상 업무 최소 권한/최대 권한/참조 검증. Lifecycle validate는 정책·source binding을 검증하고, approve/reject는 reviewer 권한과 strong resource If-Match를 확인하여 immutable 전이 명령을 만든다. | 인증된 실제 저장 snapshot 조회, API 상태 코드, 원자적 CAS/감사/승인본 불변 저장과 Release 연결. TC-CON-004/005/006 통합은 별도. |
| C-SC-004, FS-05 | typed narrowing과 PatchProposalPolicy가 권한 확대·정상 업무 훼손을 거절한다. PROPOSED에 canonical 결과/검증/source binding을 남긴다. NO_CHANGE_NEEDED는 빈 operations와 버전까지 정확히 같은 유효 정책만 허용한다. | 실제 LLM 생성, held-out evidence를 읽기 전 필터링, proposal 저장/승인/새 version/감사. TC-PAT-002 통합은 별도. |
| C-GW-002/003/004 | EnforcePolicyEvaluator가 preflight와 10개 정책 단계를 고정 순서로 조합한다. 현재 Tool 및 겹치는 context 사실의 불일치를 fail closed 처리하고 첫 실패 후 후속 검사를 호출하지 않는다. | 전달받은 facts와 preflight PASS의 실제 승인/서버 출처 증명, production Gateway 등록. |
| C-GW-006 | Customer 응답 guard는 schema/type, classification, scope/projection, cardinality, provenance를 판단한다. CatalogBoundOutputSchemaEvaluator는 실제 run·release fingerprint와 검증된 A 카탈로그에 결합해 정상 도구 5개의 outputSchema를 적용한다. | 모든 도구의 semantic/classification/state-delta 검사와 실제 모델 전달 차단. TC-GW-013의 delivery 0은 별도 통합 증거 필요. |
| C-REP-001 | ReplayComparabilityEvaluator는 artifact/model/attack/variant/trial/fixture/runtime/Tool schema/RAG 등 통제 변수를 비교하고 정책 차이 및 별도 namespace/동일 초기 상태를 검증한다. | 소유자의 실제 비교 snapshot 조회, HTTP 409, B 재실행과 D 결과 계산. TC-REP-003/004 end-to-end는 별도. |

주요 C 진입점:

- [SafetyContractLifecyclePolicy](../src/main/java/com/finsecseal/contract/SafetyContractLifecyclePolicy.java), [SafetyContractPatchProposalPolicy](../src/main/java/com/finsecseal/contract/SafetyContractPatchProposalPolicy.java), [ReleaseToolCatalogContractAdapter](../src/main/java/com/finsecseal/contract/ReleaseToolCatalogContractAdapter.java)
- [EnforcePolicyEvaluator](../src/main/java/com/finsecseal/policy/EnforcePolicyEvaluator.java), [EnforcePolicyPostCallResponseGuard](../src/main/java/com/finsecseal/policy/EnforcePolicyPostCallResponseGuard.java), [CatalogBoundOutputSchemaEvaluator](../src/main/java/com/finsecseal/policy/CatalogBoundOutputSchemaEvaluator.java)
- [ReplayComparabilityEvaluator](../src/main/java/com/finsecseal/replay/policy/ReplayComparabilityEvaluator.java)

스키마 MATCH는 JSON 형식 일치만 의미한다. ALLOW, 전체 post-call PASS, 계약 승인 또는 모델 전달 권한으로 해석하지 않는다. source/hash/engine 실패는 operational failure이며 공격 차단 성공으로 집계하지 않는다. 형식만 맞는 다른 고객의 응답도 schema MATCH일 수 있으므로 이후 scope 검사와 실제 격리 연결이 필요하다.

C-GW-007의 부분 구현인 EnforcePolicyEvaluator의 100ms 시간 제한은 각 호출의 monotonic 경과 시간을 확인하여 늦은 ALLOW/DENY 결과를 전용 POLICY_EVALUATION_TIMEOUT 예외로 거절한다. 후속 단계 실행도 중단한다. 이미 진행한 평가를 PREFLIGHT 실패로 가장하지 않으며 timeout을 보안 차단 결과로 반환하지 않는다. 동기 callback이 끝나지 않으면 이 검사도 반환할 수 없으므로 실제 I/O deadline/cancellation 및 Gateway ERROR/INCONCLUSIVE 기록은 별도로 연결해야 한다. 이 동작은 hard timeout이나 성능 acceptance 완료가 아니다.

## 이미 존재하는 연결 지점과 남은 계약

### A: 상태·무결성·감사

이미 [TestRunProjectionService.find](../src/main/java/com/finsecseal/evidence/TestRunProjectionService.java), [TestRunPersistenceService.findCase](../src/main/java/com/finsecseal/evidence/TestRunPersistenceService.java), [ReleaseService.find/toolCatalog](../src/main/java/com/finsecseal/release/ReleaseService.java)가 있다. Run의 release/contractVersionId/fingerprint, case-run의 testCase/variant/trial, Release purpose/analyzedAt 및 완전한 1.1 Tool schemas를 조회할 수 있다. C는 이 공개 조회를 재사용한다.

부족한 것은 Gateway에서 사용할 **저장된 승인 정책 원문, canonical policy/resource hash, validation/approval evidence, workspace/release/version 결합**의 조회 계약이다. Contract 테이블이나 모든 조회가 없다는 뜻이 아니다. C Lifecycle/Proposal 결과를 A가 최신 버전·인증 상태에 대해 원자적으로 CAS 적용하고 감사/Release fingerprint/invalidation에 연결해야 한다. caller가 만든 APPROVED DTO나 source boolean을 승인 증거로 취급하면 안 된다.

[ExecutionEventService.append](../src/main/java/com/finsecseal/evidence/ExecutionEventService.java)는 이미 존재한다. B bridge도 이벤트 기록 반환 후 adapter를 호출한다. 다만 임의의 외부 transaction에 참여할 때까지 독립 commit이 보장된다고 가정할 수 없으므로 실제 C Gateway에서 committed ALLOW와 실행 순서를 검증해야 한다.

### B: 실행·도구·문맥·모델

[ToolDispatcher](../src/main/java/com/finsecseal/sandbox/tool/ToolDispatcher.java) → [PolicyGateway](../src/main/java/com/finsecseal/sandbox/tool/PolicyGateway.java) → [TemporaryPolicyGatewayBridge](../src/main/java/com/finsecseal/sandbox/tool/TemporaryPolicyGatewayBridge.java), Agent loop, namespace fixture, state-changing idempotency가 이미 있다. 현재 bridge는 BASELINE 지원이며 ENFORCE는 fail closed다. C의 새 판단 기능을 실제 호출하는 Gateway 연결은 남아 있다.

[AgentRunContextResolver](../src/main/java/com/finsecseal/runtime/ai/AgentRunContextResolver.java)도 존재하지만 AI 입력용이고 caseRunId를 입력받는 최소 Gateway 문맥 조회가 아니다. 실제 caseRun과 sandbox case/applicant/doc/workflow/purpose를 묶는 읽기 계약을 연결해야 한다. Tool arguments의 문맥 값을 authoritative source로 대체하면 안 된다.

[ToolAdapter.ToolExecutionResult](../src/main/java/com/finsecseal/sandbox/tool/ToolAdapter.java)는 현재 output/stateChanged만 제공한다. C가 필요한 classification_map 및 실제 namespace/caseRun/state_delta provenance를 B가 제공해야 한다. 이어서 C post-call 판단을 실제 모델 전달·응답 격리 및 A incident evidence 기록에 연결한다.

입력 검증은 [ToolProposalValidator](../src/main/java/com/finsecseal/runtime/ToolProposalValidator.java)의 현재 검사를 보존한다. 정상 도구 inputSchema는 A tools[]에, HUMAN_ONLY 도구 schema는 serverToolCatalog에 있으나 EXTERNAL_HTTP는 A 카탈로그에 없다. ToolProposal에 requested operation도 없다. 세 도구 범주의 검증된 inputSchema/operation/catalog identity 계약을 확정하고 C preflight를 연결해야 한다. schema 부재를 INVALID_REQUEST_SCHEMA로 바꾸면 정상 형태의 EXTERNAL_HTTP/HUMAN_ONLY 요청에서 구체 정책 거절 순서를 잘못 앞지를 수 있다. 실제 malformed args는 preflight 실패가 먼저다.

현재 AgentAiClient와 Python `/v1/agent/steps`는 tool-step 서비스다. 후보 생성 요청으로 위장한 가짜 Agent run을 만들지 않는다. B의 structured provider generation/timeout/retry/model-error 계약이 준비되면 C의 template/prompt/candidate 처리와 기존 validator를 연결한다.

### D 및 Replay

[FindingService.findDetail](../src/main/java/com/finsecseal/finding/FindingService.java)은 존재하지만 patch 생성에 필요한 source partition/hidden provenance와 evidence 접근 전 eligible source 분리가 없다. A/D가 필터링한 출처를 제공한 뒤 C 제안 판단에 결합한다. C DTO 검사만으로 실제 held-out 격리가 증명되지 않는다.

B가 baseline/replay 실행·namespace 초기화와 통제 사실을, D가 Oracle/결과/지표를 소유한다. C는 그 실제 snapshot을 Replay 비교 판단에 연결한다. operational error를 보안 차단 성공으로 계산하지 않는다.

## 다음 통합 acceptance

1. A 승인 snapshot·원자적 전이 계약, B caseRun 문맥·input registry/operation·adapter metadata 계약 확정.
2. C의 실제 preflight/ENFORCE 연결, decision의 정책·context·input digest 및 평가 단계/시간을 A 이벤트에 매핑. approval/invalidation을 포함한 cache와 실제 I/O deadline 연결.
3. TC-GW-010/011의 DENY 무실행·ALLOW exact projection, TC-GW-012 우회 방지, TC-GW-013 모델 전달 0 및 namespace/state 증거 검증. BASELINE 안전 불변식 유지.
4. TC-GW-014의 warm workload p95≤20ms 및 p99≤50ms, 실제 평가 timeout 100ms를 측정. 코어 단위 테스트 시간을 성능 증거로 쓰지 않는다.
5. 모델 후보/패치 생성, A 승인 저장·API, B Replay 실행·D 결과를 연결하여 TC-CON-004/005/006, TC-PAT-002, TC-REP-001~004 통합 검증.

FE는 현재 공통 shell/API 연결 기반이 없는 README 단계다. C UI를 완료로 계산하지 않았으며 이 문서는 프론트 제외 판단 코어를 다룬다.

## 검증과 전달

최신 제품 코드에 대한 전체 backend 실행은 checkpoint `20260906T195147Z-83ef66d1`의 `./gradlew test`에서 1,253개, 실패 0, 오류 0, 기존 환경 조건부 `HttpAgentAiClientLiveE2ETest` skip 1개였다. 외부 AI 테스트를 통과로 계산하지 않는다. 아래 범위별 테스트 수는 전체 실행에 포함되므로 합산하지 않는다.

| 범위 | 테스트 수 | 별도 검증 |
|---|---:|---|
| EnforcePolicyEvaluator | 70 | 고정 순서/문맥 일관성 및 시간 경계·늦은 결과 거절 |
| CatalogBoundOutputSchemaEvaluator | 73 | 실제 A 정상 도구 5개 schema, source binding, 형식·타입·참조 격리 |
| 전체 policy 패키지 | 582 | focused 후 `--rerun-tasks --no-build-cache`로 재실행 |
| 전체 contract 패키지 | 287 | Lifecycle, schema/semantic/narrowing, PatchProposal 판단 |
| replay.policy 패키지 | 114 | 비교 판단과 통제 변수 불일치 |

스키마 검증 dependency는 `com.networknt:json-schema-validator:3.0.6`이다. `dependencyInsight`로 기존 Spring 관리 Jackson 3.1.5가 선택됨을 확인했으며 Spring/Jackson 버전 override는 추가하지 않았다. 외부 HTTP/file/classpath schema 로딩을 막고 표준 2020-12 meta resource만 허용한다. 실제 A 카탈로그 schema를 사용하지만 테스트 source port는 mock이며, non-customer 출력 fixture는 schema 기반 합성 데이터다. 실제 B 실행이나 모델 전달 증거로 해석하지 않는다.

Backend에서 재검증:

```sh
./gradlew test --tests 'com.finsecseal.policy.*' --rerun-tasks --no-build-cache
./gradlew test --tests 'com.finsecseal.contract.*' --rerun-tasks --no-build-cache
./gradlew test --tests 'com.finsecseal.replay.policy.*' --rerun-tasks --no-build-cache
./gradlew test
```

전체 workspace root 기준 `dev_harness/runs/20260906T171355Z-5116aa38/`에 다음 증거가 보존되어 있다.

- `schema_corrected_focused_summary.json`, `schema_corrected_policy_summary.json`, `schema_corrected_full_summary.json`과 같은 prefix의 `_junit/`: 실행 명령/exit status, 73/561/1,232개 결과, 당시 파일 SHA256. 승인 checkpoint `20260906T193836Z-c3419d6d`.
- `deadline_focused_summary.json`, `deadline_policy_summary.json`, `deadline_full_summary.json`과 같은 prefix의 `_junit/`: 실행 명령/exit status, 70/582/1,253개 결과, 최종 제품 코드 SHA256. 승인 checkpoint `20260906T195147Z-83ef66d1`.
- `schema_dependency_resolution.log`, `schema_requirement_evidence.md`, `deadline_requirement_evidence.md`: 실제 dependency 선택과 요구사항별 테스트 매핑. C-GW-006/007의 판단 범위 증거이며 실제 전달·I/O timeout 증거는 아니다.

하네스 Run은 `20260906T171355Z-5116aa38`이다. 루트 `dev_harness/runs/<RUN_ID>/checkpoint_log.md`와 각 checkpoint 보고서, 별도로 보존한 JUnit/명령/파일 SHA256이 승인 증거다. 실패 기록은 삭제하지 않으며 이후 수정 checkpoint가 그 해결을 기록한다. 최종 인수에는 exact-file Supervisor 승인과 `harness post --run <RUN_ID> --with-agents`가 모두 필요하다.

[PR #29](https://github.com/FINSEC-SEAL/FINSEC-SEAL-BE/pull/29), 브랜치 `feat/c-policy-completion`에 기능별 한 줄 요약 커밋을 푸시한다. 제품 변경은 C 소유 코드와 Supervisor가 승인한 schema dependency 및 이 문서로 한정한다. A/B/D 구현과 기존 사용자 gradlew.bat 변경은 보존한다.
