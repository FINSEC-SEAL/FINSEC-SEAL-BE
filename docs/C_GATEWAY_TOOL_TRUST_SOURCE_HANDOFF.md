# C Gateway Tool Trust 기준 입력

승인 계약 조회 결과에서 기존 `PolicyToolTrustFacts`에 필요한 **기대 Release 바인딩과 승인된 신뢰 정책**을 제공합니다. 명세 `16_POLICY_GATEWAY_SPEC.md`의 10단계와 `TC-GW-008`을 지원하는 출처 연결입니다.

연동에는 1단계 카탈로그 바인딩 확장과 2단계 승인 출처 accessor 연결이 모두 필요합니다. 아래는 두 단계의 최종 호출 계약이며, 카탈로그만 확장한 중간 버전에서는 승인 출처 accessor를 사용할 수 없습니다.

## 진입점과 타입

- `contract/ReleaseToolCatalogContractAdapter.load(UUID releaseId, String actorId)`
  - 반환: `SourceBoundCatalog`.
  - 추가 accessor: `List<PolicyToolTrustFacts.ReleaseToolBinding> releaseToolBindings()`.
- `policy/GatewayApprovedPolicySourceService.load(UUID runId, UUID testCaseRunId, ReviewerContext reviewer)`
  - 반환: `ApprovedPolicySource`.
  - 추가 accessor: `List<ReleaseToolBinding> releaseToolBindings()`, `ToolTrustPolicy toolTrustPolicy()`.
  - 기존 인증 컨텍스트·승인·Run/CaseRun·현재 Release 바인딩과 writable `REPEATABLE_READ` 조건을 유지합니다. 호출 계약은 [기존 출처 인계서](C_GATEWAY_APPROVED_POLICY_SOURCE_HANDOFF.md)를 따릅니다.

모든 반환 목록은 불변입니다. 조회 결과는 출처 스냅샷이며 실행 허가, preflight PASS 또는 전체 Gateway 결정을 뜻하지 않습니다.

## 기준값의 출처

기존 A `ReleaseService.toolCatalog()`를 한 번 호출해 검증된 JSON을 복사합니다. 같은 복사본으로 semantic catalog와 다음 바인딩을 만듭니다. 추가 저장소 조회는 없습니다.

| 반환 필드 | 출처 |
|---|---|
| `toolName`, `version` | 검증된 `manifest.tools`의 정확한 값 |
| `enabled` | `true`: A가 모든 manifest Tool과 활성 `release_tools` 행의 일치를 검증함 |
| `schemaDigest` | `hash({"inputSchema": inputSchema, "outputSchema": outputSchema})` |
| `descriptionDigest` | `hash({"description": description})` |
| `requireTrustedTool` | 승인 정책 `/toolTrust/requireTrustedTool` |
| `allowedTrustLevels` | 승인 정책 `/toolTrust/allowedTrustLevels`를 기존 `TrustLevel` enum으로 변환 |

`hash`는 A의 `ReleaseCatalogWriter`·`ReleaseIntegrityVerifier`와 동일하게 `CanonicalJsonService.canonicalize()` 후 `DigestService.sha256()`를 적용합니다. 객체 키 정렬, NFC와 LF 정규화, 정규화 후 키 충돌 거절을 유지하며 설명의 의미 있는 공백이나 스키마 배열 순서를 임의 변경하지 않습니다. 설명·스키마 원문은 새 바인딩에 담지 않습니다.

바인딩은 Tool 이름순이며 현재 정상 Tool 5개를 포함합니다. 별도 `serverToolCatalog`의 인간 전용 `LOAN_DECISION_UPDATE`를 활성 실행 바인딩으로 만들지 않습니다. `allowedTools`와 활성 카탈로그도 구분합니다.

## 실패 전달과 호환성

- 카탈로그에서 필요한 버전·설명·스키마 입력이 누락되거나 타입이 잘못되었거나 해시 계산이 실패하면 기존 `CatalogAdapterException`의 `INVALID_ENABLED_TOOL_CATALOG`를 전달합니다. 원문이나 원인 예외를 포함하지 않습니다. 전체 Manifest 검증은 기존 A 책임을 유지합니다.
- 승인 출처의 바인딩 집합은 enabled semantic catalog와 정확히 일치해야 합니다. 누락·추가·중복·비활성·잘못된 바인딩은 `PolicySourceException(CATALOG_BINDING_INVALID)`로 거절합니다.
- 잘못된 승인 정책은 기존 실제 validator와 `POLICY_INVALID`로 거절하며 신뢰 정책 기본값을 만들지 않습니다. A의 권한·조회·무결성 오류 전달과 다른 기존 실패 코드는 유지합니다.
- `SourceBoundCatalog`의 기존 6인자 생성자는 semantic-only 소비자를 위해 유지됩니다. 이 생성자의 바인딩은 빈 목록입니다. 생성·Preview 검증에서 사용할 수 있지만 Gateway 승인 출처에서는 불완전한 기준 입력으로 거절합니다.

## B 연동 입력과 남은 범위

호출자는 요청한 Tool과 **독립적으로 관찰한** registry·Release fingerprint를 함께 제공해야 기존 평가기를 호출할 수 있습니다.

```java
var facts = new PolicyToolTrustFacts(
        requestedTool,
        source.catalog().releaseFingerprint(),
        observedReleaseFingerprint,
        observedRegistryEntries,
        source.releaseToolBindings(),
        source.toolTrustPolicy());
```

`observedRegistryEntries`는 기존 `ToolRegistryEntry` 목록으로 실제 Tool 이름·버전·신뢰 수준·스키마/설명 해시가 필요합니다. 이 기능은 해당 관찰값을 생성하지 않습니다. 기대값을 복사해 관찰값으로 사용하면 무결성 비교가 성립하지 않습니다.

A의 계약 저장·승인·Release 무결성 및 감사 기록, B의 registry 관찰·Runtime/Dispatcher 실행 연결, D의 Run/Oracle/Replay 결과 연결은 각 담당자의 영역입니다. 실제 `ALLOW` 이벤트 commit 이후 호출, 응답 격리, Run 중단, FA-01~03 차단과 no-call/no-leak/no-state-delta의 실행 증거는 이번 기준 입력 연결의 완료 범위에 포함되지 않습니다.

검증은 A 해시 규칙과의 일치, 실제 PostgreSQL에 저장된 5개 바인딩 비교, 불변성·실패 거절, 기존 승인 조회의 트랜잭션·잠금·접근 감사 2건·Tool 미실행 단언 및 생성/Preview 회귀를 포함합니다.
