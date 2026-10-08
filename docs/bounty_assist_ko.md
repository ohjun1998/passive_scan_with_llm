# 증거 기반 버그바운티 자동화 사용 설명서

## 1. 어떤 부분이 자동화되는가

GitHub Actions는 기존처럼 URL과 생존 응답을 모읍니다. 최종 암호화 ZIP에는 `bounty_seed.jsonl`이 추가됩니다. Plus 로그인과 계정별 재실행은 사용자 PC에서 수행합니다. 이 변경은 공개 GitHub Actions에 Plus 인증 정보를 등록하지 않으며 외부 대상으로 테스트를 실행하거나 Discord 메시지를 보내지 않습니다.

`run`은 기능을 우선순위로 정렬하고 표본의 정상 응답을 확보합니다. 설정된 권한 정책 검증을 실행한 뒤 Codex가 최대 3개의 추가 가설을 구조화된 계획으로 생성합니다. 실행 결과를 다음 라운드에 전달해 후속 검증을 선택합니다. 기본은 기능 30개, 기능당 표본 5개, AI 최대 12회, HTTP 최대 200회, 최대 2라운드입니다.

구독 한도가 무제한이라는 뜻은 아닙니다. 호출/프롬프트 크기를 제한하고 제공된 사용량을 저장하지만 **정확한 토큰 수를 사전에 보장하거나 Plus 한도를 우회하지 않습니다.** 기본 추론 설정은 `low`입니다. `codex.adaptive_reasoning: true`를 설정하면 이전 권한 후보 또는 일관된 응답 차이가 있는 그룹에서 `review_effort`(기본 `medium`)를 사용합니다. 단순 반사·응답 실패만으로 추론 수준을 높이지 않습니다. 모델 이름은 비워 두면 CLI 기본 모델을 사용합니다. 계정에서 제공되는 모델과 추론 수준을 지정해야 합니다.

## 2. 입력 자료 준비

| 입력 | 알 수 있는 것 | 한계 |
|---|---|---|
| URL TXT | 경로·쿼리 | 기본 GET 가설; 실제 메서드·인증·본문은 모름 |
| httpx JSONL / bounty_seed.jsonl | URL·생존 상태·서버·기술 정보 | 캡처된 실제 업무 요청을 대체하지 못함 |
| HAR | 메서드·헤더·본문·캡처 응답 | 계정 이름과 소유자는 가져올 때 지정 필요 |

```bash
python -m bounty_assist --workspace .bounty-work import urls.txt
python -m bounty_assist --workspace .bounty-work import capture_a.har --session user_a --owner user-a
python -m bounty_assist --workspace .bounty-work import capture_b.har --session user_b --owner user-b
python -m bounty_assist --workspace .bounty-work inventory --output inventory.json
```

`--workspace`는 하위 명령 앞에 둡니다. `inventory.json`에서 `id`, `group`, 계정, 소유자를 확인할 수 있습니다. 같은 요청의 서로 다른 응답 캡처도 보존합니다. 기능 묶음에서 분석되지 않은 값도 삭제하지 않습니다.

HAR의 Cookie·Authorization·이름으로 식별 가능한 토큰 헤더는 가져올 때 제거합니다. 재실행은 설정된 세션만 사용합니다. URL·본문에 자격 증명 또는 CSRF가 포함된 요청은 자동 재실행을 차단합니다. 이를 단순 제거하면 인증/업무 동작이 깨질 수 있으므로 별도 세션 갱신 어댑터나 수동 검증이 필요합니다. multipart와 본문 바이트가 누락된 업로드도 자동 재실행하지 않습니다.

## 3. 계정과 허용 범위

`origins`는 프로토콜·호스트·포트가 포함된 정확한 허용 범위입니다. 와일드카드를 쓰지 않습니다. `https://app.example.com`과 `https://app.example.com:8443`은 다른 대상입니다.

```json
{
  "origins": ["https://app.example.com"],
  "sessions": {
    "anonymous": {"origins": [], "headers_env": {}},
    "user_a": {
      "origins": ["https://app.example.com"],
      "headers_env": {"Cookie": "BOUNTY_COOKIE_A"},
      "health": {
        "url": "https://app.example.com/api/me",
        "json_pointer": "/id",
        "equals": "user-a"
      }
    }
  }
}
```

Bearer 인증이면 `headers_env`를 `{"Authorization":"BOUNTY_BEARER_A"}`로 설정하고 환경 변수에 `Bearer 실제토큰`을 넣습니다. 계정마다 인증 헤더를 완전하게 공급하세요. 환경 변수가 없으면 익명 계정으로 대체하지 않고 시작을 중단합니다.

`health`는 해당 세션이 **의도한 사용자/역할**인지 확인하는 읽기 요청입니다. 실제 응답이 `{"user":{"id":123}}`이면 `/user/id`와 숫자 `123`을 사용합니다. 문자열 `"123"`과 숫자 `123`은 다르게 비교합니다. 관리자·다른 테넌트 계정도 같은 방식으로 추가할 수 있습니다.

세션 자격 증명은 해당 세션의 `origins`에만 보냅니다. DNS 결과를 검사하고 선택한 주소로 연결을 고정하며 HTTPS의 호스트 검증을 유지합니다. 외부 응답의 리다이렉트는 따라가지 않습니다. 로컬 데모/승인된 내부 테스트에서는 `allow_private: true`를 명시해야 합니다.

## 4. 권한 정답표 설정

취약점 후보를 판단하려면 다음을 알아야 합니다.

1. 객체를 읽을 수 있는 소유자 계정.
2. 해당 객체를 읽을 수 없어야 하는 계정 목록.
3. 정상 소유자 응답에서 확인할 수 있는 **비공개 객체의 실질적인 증거**.
4. 그 증거가 나오지 않아야 하는 음성 대조 요청.

`inventory.json`의 요청 ID를 사용하면 URL이 같은 여러 메서드·계정의 요청을 구분할 수 있습니다.

```json
{
  "policies": [
    {
      "request_id": "inventory에 있는 A의 비공개 주문 요청 ID",
      "owner_session": "user_a",
      "denied_sessions": ["user_b", "anonymous"],
      "json_pointer": "/internalNote",
      "equals": "A가 테스트 객체에 설정한 고유한 비공개 표식",
      "control_request_id": "존재하지 않는 객체 등의 가져온 대조 요청 ID"
    }
  ]
}
```

단순히 입력 ID를 돌려주는 필드, 공개 정보 또는 모든 사용자에게 보이는 메시지를 증거로 선택하지 마세요. 공유된 객체는 사용자 B에게도 허용될 수 있으므로 실제 정책에 따라 `denied_sessions`를 정해야 합니다. 이 설정을 AI가 추측하지 않습니다.

ID 대신 `request_url`, `owner_session`, `control_url`을 쓸 수도 있습니다. 해당 URL이 정확히 하나의 가져온 요청으로 연결될 때만 허용됩니다. 대조 요청은 같은 origin의 다른 요청이어야 하며 직접 가져와야 합니다.

자동 검증은 소유자·다른 계정 각 2회와 대조 요청 2회를 사용합니다. 계정 신원이 확인되고 소유자/차단 계정 모두 지정한 비공개 증거를 반환하며 대조에서는 반환하지 않을 때 `auth_candidate`로 기록합니다. 이는 **보고서 후보**이며 정책·영향·서비스 특성을 사람이 최종 확인해야 합니다.

이 방식은 알려진 A/B 객체를 서로 교차 접근시키는 검증에 적합합니다. 숫자 ID를 대량 열거하지 않습니다. JSON 기반 읽기 증거가 중심이며 HTML/SOAP·쓰기 작업의 권한은 전용 판정 규칙을 추가해야 합니다.

## 5. AI가 생성하는 계획

계획 필드는 `request_id`, `kind`, `session`, `location`, `field`, `value`, `control`, `hypothesis`, `expected_evidence`, `prerequisites`입니다. AI가 요청 URL이나 셸 명령을 새로 지정하는 구조가 아닙니다.

| kind | 실행 내용 | 결과의 의미 |
|---|---|---|
| auth | 가져온 요청을 다른 세션으로 재실행 | 정답표·신원·대조가 갖춰지면 권한 후보 |
| reflection | 로컬에서 만든 무해한 표식으로 기존 입력 교체 | 반사 맥락을 찾는 신호; XSS 확정 아님 |
| compare | 테스트/대조 입력을 교차로 각 2회 보내 비교 | 일관된 응답 차이; SQLi 등 확정 아님 |
| manual | 필요한 조건·검증 절차 기록 | 자동 요청 없음 |

query와 form은 기존 키, JSON은 기존 JSON Pointer, path는 기존 단일 세그먼트만 바꿉니다. 변경 값은 256자로 제한합니다. 메서드를 바꾸거나 다른 호스트로 요청을 생성할 수 없습니다. 단순 값 반사와 일부 시각/추적 필드는 응답 차이 비교에서 제외합니다. 지연 기반 SQLi는 이 실행기로 확정하지 않습니다.

Codex는 임시 작업 폴더에서 구조화된 계획을 출력합니다. 사용자 CLI 설정을 읽지 않도록 실행하고 셸·웹 검색·MCP를 비활성화합니다. 요청/응답에 있는 지시문은 신뢰하지 않도록 프롬프트에 명시합니다. 도구 실행 이벤트가 있으면 계획을 거부합니다. 설치된 CLI는 공식 옵션을 지원하는 최신 버전을 사용하세요.

## 6. 실행과 재개

```bash
python -m bounty_assist run --config config.local.json --planner codex
# AI 없이 정상 요청과 명시한 권한 정책만 검증
python -m bounty_assist run --config config.local.json --planner none
# 네트워크 요청 없이 기존 결과 보고서 다시 생성 (세션 환경 변수는 설정 필요)
python -m bounty_assist report --config config.local.json --output reports/bounty_report.html
```

Codex가 없거나 구독 인증이 아니면 대상 트래픽을 보내기 전에 중단합니다. `codex login status`에서 ChatGPT 인증을 확인하세요. 일반 OpenAI API 키는 Plus 구독에 포함되지 않으며 이 연결에서는 사용하지 않습니다.

기본 설정은 GET/HEAD입니다. 실제 POST JSON 조회가 필요하면 `allowed_methods`에 POST를 추가할 수 있지만 쓰기 작업의 부작용과 프로그램 정책을 확인해야 합니다. 로그아웃·삭제 등 경로는 기본 제외 패턴으로 차단합니다.

요청 수는 실패/중단 시도도 포함해 누적합니다. AI 타임아웃·실패도 호출 예산을 소비합니다. HTTP 429/503이면 자동 반복 폭주 대신 중단 상태를 저장합니다. 종료 코드는 완료 `0`, 설정/실행 오류 `1`, 예산/백오프로 중단 `2`입니다.

같은 `.bounty-work`로 재실행하면 완료된 요청과 AI 라운드를 재사용합니다. 기본 증거 유효기간은 900초입니다. 완료된 그룹의 체크포인트가 유효하면 건너뛰어 남은 그룹부터 처리합니다. 그룹 제한에 도달했을 때 완료로 표시하지 않습니다. 계정 쿠키나 정책이 바뀌면 별도 검증 맥락으로 다시 테스트합니다. 예산은 작업 폴더 전체에 누적되므로 필요하면 제한을 명시적으로 늘리거나 새 작업 폴더로 별도 평가를 시작하세요. 대상 범위가 달라지면 새 작업 폴더를 권장합니다.

## 7. 결과와 데이터 취급

| 상태 | 의미 |
|---|---|
| auth_candidate | 권한 우회 증거 후보, 최종 검토 필요 |
| reflection_signal | 입력 반사 확인 |
| differential_signal | 일관된 테스트/대조 차이 |
| not_reproduced | 이번 조건에서는 재현 안 됨 |
| inconclusive | 세션·정책·응답·대조 부족 또는 요청 실패 |
| manual_required | 전용 도구·추가 맥락 필요 |
| rejected | AI 계획이 실행 규칙을 충족하지 못함 |

원본 캡처와 HTTP 응답은 로컬 SQLite에 남습니다. POSIX 환경에서 폴더는 0700, DB/보고서는 0600 권한으로 만듭니다. Windows에서 `chmod`는 같은 접근 격리를 보장하지 않으므로 본인 계정의 비공개 폴더에 두고 Windows ACL을 적용하세요. AI 입력과 보고서에는 알려진 세션값·민감 키·JWT·이메일·일부 XML 자격 증명을 마스킹하고, 동일 값은 같은 별칭으로 표시합니다.

마스킹은 완전한 DLP가 아닙니다. 임의 필드명의 비밀·경로 토큰·업무 개인정보는 자동 식별하지 못할 수 있으므로 프로그램의 외부 AI 전송 정책과 캡처 내용을 확인하세요. 모델에 보내는 표본에는 응답 일부가 포함됩니다. 원본 HAR·DB·쿠키·실제 대상 보고서를 공개 Git에 올리지 않습니다.

## 8. 탐지율을 평가하는 방법

```bash
python -m unittest discover -s tests -v
python examples/demo_bounty.py
```

로컬 데모는 취약한 객체 접근, 조치된 객체 접근, 입력 반사를 비교합니다. 계획기는 명시적인 모의 객체이며 GPT가 아닙니다. 공식 CLI 호출·인증·출력/사용량 처리도 단위 테스트에서는 모의 실행으로 확인합니다.

실제 탐지율은 알려진 취약/정상 기능을 함께 준비하고 실제 로그인된 Codex로 별도 측정해야 합니다. 탐지율·오탐률·미확인 비율과 후보 한 건당 HTTP/AI 사용량을 함께 비교하세요. 새 테스트 규칙은 정상 기능에서의 오탐 방지와 조치 후 재검증까지 확인한 뒤 추가하는 것이 좋습니다.

## 공식 자료

- [Codex 인증](https://developers.openai.com/codex/auth)
- [비대화형 실행과 JSON Schema](https://developers.openai.com/codex/noninteractive)
- [CLI 설정](https://developers.openai.com/codex/config-reference)
- [Codex 구독 및 사용량](https://developers.openai.com/codex/pricing)

## 9. 사용량과 사전 점검

```bash
python -m bounty_assist doctor
# 실제 모델 1회 호출; 검사 대상 HTTP 요청 없음
python -m bounty_assist doctor --live
python -m bounty_assist usage
# 본인 계정 사용량을 확인한 뒤 미확인 호출을 명시적으로 인정하고 재개
python -m bounty_assist usage --acknowledge-unknown
# 실제 GPT와 로컬 테스트 서버; 별도 실행마다 새 평가 작업 폴더
python examples/demo_bounty.py --live
```

`doctor`의 로그인 상태와 옵션 점검만으로 모델 호출 성공을 판단하지 않습니다. `doctor --live`가 구조화된 응답을 받았을 때 `live_model_success: true`를 표시합니다. `--live`는 Plus 사용량을 소비합니다.

`max_context_chars`(기본 24000)는 모델에 전달하는 데이터 JSON의 문자 수 제한이며 토큰 수가 아닙니다. 필요하면 이전 결과·캡처 응답·표본을 줄이고 JSON 전체를 유지합니다. 단일 요청도 제한에 맞지 않으면 호출을 중단합니다.

`max_model_tokens`(기본 80000)는 CLI가 반환한 입력+출력 토큰의 누적 중단 기준입니다. 캐시 입력은 입력의 일부이고 추론 토큰은 출력의 일부여서 추가 합산하지 않습니다. 정확한 사전 토큰 상한이 아니며 마지막 호출에서 초과할 수 있습니다. 기준에 도달하면 다음 신규 모델 호출을 막습니다. Plus 계정의 잔여 한도나 실제 API 요금과 같지 않습니다. 기존 버전 작업 폴더의 과거 사용량은 소급 집계되지 않으므로 새 작업 폴더에서 평가하세요.

실패·타임아웃·누락된 사용량은 정확히 계산할 수 없어 미확인 호출로 기록하고 신규 호출을 중단합니다. 계정 사용량을 확인하고 `usage --acknowledge-unknown`으로 재개할 수 있습니다. 알려진 토큰과 HTTP/AI 호출 카운터는 초기화되지 않습니다. 프로세스가 강제 종료된 호출도 사용량이 누락될 수 있습니다.

지원되지 않는 업로드·OAST·브라우저 실행·업무 흐름은 여전히 수동 검증 계획으로 기록됩니다. 이 변경은 전용 실행기가 구현됐다는 뜻이 아닙니다.
