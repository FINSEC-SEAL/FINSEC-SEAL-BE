# C 계약 검증 Preview API

제출 전 Safety Contract 초안을 실제 Release의 검증된 Tool 카탈로그와 대조한다. 필수 권한 누락, 허용 범위를 넘는 고객·필드·외부 전송·고영향 권한 설정, 잘못된 스키마를 오류 위치와 사유로 확인할 수 있다. 외부 LLM 없이 실행된다.

`VALID`는 이 초안이 해당 카탈로그와 C 검증 규칙을 통과했다는 뜻이다. 계약을 저장하거나 `VALIDATED`/`APPROVED`로 전환하지 않으며, Tool 실행 권한이나 Release PASS를 부여하지 않는다.

## 로컬 실행

BE 저장소 디렉터리에서 실행한다. PostgreSQL과 `FINSEC_DATA_ENCRYPTION_KEY_BASE64`는 기존 [로컬 설정](../README.md#local-verification)을 사용한다. 기존 DB를 사용할 때는 그 DB에 사용하던 암호화 키를 유지한다.

```sh
docker compose up -d postgres
SPRING_PROFILES_ACTIVE=local ./gradlew bootRun --args='--finsec.contract-preview.enabled=true --server.address=127.0.0.1 --server.forward-headers-strategy=none'
```

기본 설정에서는 API가 비활성화되어 있다. `local` 프로필과 명시적인 `true` 설정이 모두 필요하고, 루프백 주소와 전달 헤더 처리 비활성화 설정을 요구한다. 위 명령은 현재 PC의 `127.0.0.1:8080`에서 사용한다. `Forwarded`와 모든 `X-Forwarded-*` 헤더를 거부한다. `X-Actor-Id`는 감사용 표시이며 인증된 reviewer 권한을 뜻하지 않는다.

## 정상 계약과 위반 계약을 직접 확인

다음 예제는 기존 A API로 합성 Agent와 Manifest 1.1 Release를 새로 만든 뒤, 실제 C Preview API를 두 번 호출한다. 입력은 저장소의 기존 합성 fixture다. 프론트나 AI 서버는 필요하지 않다.

```sh
python3 - <<'PY'
import copy
import json
import uuid
from pathlib import Path
from urllib.request import Request, urlopen

base = "http://127.0.0.1:8080/api/v1"
fixtures = Path("src/test/resources/fixtures")

def post(path, body):
    request = Request(base + path,
        data=json.dumps(body, ensure_ascii=False).encode("utf-8"),
        headers={"Content-Type": "application/json",
                 "X-Actor-Id": "c-preview-demo",
                 "Idempotency-Key": str(uuid.uuid4())},
        method="POST")
    with urlopen(request, timeout=20) as response:
        return json.load(response)["data"]

agent_key = "c-preview-" + uuid.uuid4().hex[:12]
agent = post("/agents", {"agentKey": agent_key,
    "name": "C 계약 검증 시연", "purposeSummary": "대출서류 완전성 검토"})
manifest = json.loads((fixtures / "valid-release-manifest-v1.1.json").read_text())
manifest["agent"]["id"] = agent_key
release = post(f"/agents/{agent['id']}/releases", manifest)
policy = json.loads((fixtures / "loan-review-safety-contract.json").read_text())
path = f"/contract-validation-previews/{release['id']}"

valid = post(path, policy)
assert valid["previewOnly"] is True
assert valid["status"] == "VALID" and valid["policyHash"].startswith("sha256:")
assert valid["source"]["releaseId"] == release["id"]
print("정상 계약:", json.dumps(valid, ensure_ascii=False, indent=2))

invalid_policy = copy.deepcopy(policy)
invalid_policy["fieldPolicy"]["CUSTOMER_DATA_READ"]["allowed"].append("accountNumber")
invalid = post(path, invalid_policy)
assert invalid["status"] == "INVALID" and invalid["policyHash"] is None
assert any(issue["code"] == "FIELD_EXCEEDS_TEMPLATE" for issue in invalid["issues"])
print("과도한 필드 권한:", json.dumps(invalid, ensure_ascii=False, indent=2))
print("release_id=" + release["id"])
PY
```

## 요청과 결과

`POST /api/v1/contract-validation-previews/{releaseId}`의 body는 **계약 JSON 자체**다. `candidate` 같은 wrapper를 붙이지 않는다. `Idempotency-Key`와 공백 없는 1~120자 `X-Actor-Id` 헤더를 보낸다.

```sh
curl -sS "http://127.0.0.1:8080/api/v1/contract-validation-previews/$RELEASE_ID" \
  -H 'Content-Type: application/json' \
  -H 'X-Actor-Id: c-preview-demo' \
  -H "Idempotency-Key: $(uuidgen)" \
  --data-binary @src/test/resources/fixtures/loan-review-safety-contract.json
```

위 `RELEASE_ID`에는 앞선 예제가 출력한 Release ID를 설정한다. 정상 응답의 `data`에는 다음이 포함된다.

| 필드 | 의미 |
|---|---|
| `previewOnly` | 항상 `true` |
| `status` | 기존 C 검증기의 `VALID` / `INVALID` / `WARN` |
| `issues` | `jsonPointer`, `code`, `severity`, `message` |
| `source` | 실제 Release ID, Manifest 버전, artifact/release fingerprint, 서버 카탈로그 hash |
| `policyHash` | `VALID`일 때만 계산한 canonical 정책 hash; 나머지는 `null` |

카탈로그와 source fingerprint를 요청 body로 지정할 수 없다. 검증 사유에는 잘못 지정한 Tool/필드 이름이 포함될 수 있다. 원본 카탈로그나 전체 계약 JSON, 내부 예외 원문은 응답에 첨부하지 않는다.

| HTTP | 의미 |
|---|---|
| `200` | 초안 검증 수행 완료; `status`와 `issues` 확인 |
| `400` | JSON/UUID/body/actor 오류, 키 누락, 비정규 경로 |
| `403` | 로컬 접근 조건 불충족 또는 전달 헤더 포함 |
| `404` | Preview 비활성화 또는 `local` 프로필 아님 |
| `409` | 같은 키에 다른 요청 또는 이전 5xx 요청의 복구 대기 |
| `415` | JSON 이외 Content-Type |
| `422` | 기존 플랫폼의 요청 크기 제한(2 MiB) 초과 |
| `500` | 검증·해시 처리 실패; 검증 결과 없음 |
| `503` | 실제 카탈로그를 검증할 수 없음; 검증 결과 없음 |

Release 미존재, legacy 1.0, 저장 데이터 변조 등은 기존 카탈로그 adapter의 안전한 오류 계약에 따라 `503`으로 표시된다. 이를 초안 `INVALID`나 공격 차단 성공으로 계산하지 않는다. 경로는 루트 컨텍스트의 정규 경로를 사용하며, 퍼센트 인코딩·세미콜론으로 우회하는 경로는 거부한다.

같은 키와 같은 요청은 기존 플랫폼에 저장된 **당시 snapshot의 결과**를 재사용한다. 재검증에는 새 키를 사용한다. 기능을 끄거나 접근 조건을 위반한 요청은 저장된 결과도 받을 수 없다. 5xx가 발생한 키는 플랫폼의 `RECOVERY_REQUIRED` 상태가 되므로 같은 키로 즉시 재시도하면 `409`다. 원인을 해결한 뒤 새로운 Preview 요청에는 새 키를 사용한다.

계약·승인·Release 상태는 변경하지 않는다. 기존 A의 카탈로그 접근 감사와 HTTP idempotency 기록은 유지되므로 DB 쓰기가 전혀 없는 API는 아니다.

## 개발 검증과 남은 범위

```sh
./gradlew test --tests 'com.finsecseal.contract.SafetyContractValidationPreviewHttpIntegrationTest' --rerun-tasks --no-build-cache
./gradlew test --rerun-tasks --no-build-cache
```

HTTP 통합 테스트는 실제 Spring 서버, PostgreSQL, A 공개 서비스와 C 검증기를 연결한다. TC-CON-001/002/003의 초안 판단을 실제 호출할 수 있게 하는 부분 구현이다. 저장된 계약의 승인·거절, 생성, 실제 ENFORCE, 위험 응답 전달 격리, Replay 및 운영 오류 지표 연동은 별도 작업이다.

이 변경의 하네스 Run은 `20260906T220332Z-686f6afb`다. 이전 Run `20260906T171355Z-5116aa38`의 POST FAIL과 Supervisor BLOCKED, TP-POST-003/004 및 REG-POST-001/002는 해결되지 않았다. 이 Preview의 통합 테스트를 실제 Gateway 공격 차단 증거로 사용하지 않는다. 기반 C 코어는 [PR #29](https://github.com/FINSEC-SEAL/FINSEC-SEAL-BE/pull/29)로 `dev`에 병합되었으며 이번 기능 PR도 `dev`를 대상으로 한다.
