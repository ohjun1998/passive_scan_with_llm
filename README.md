# passive_scan_with_llm

`ohjun1998/passive-scan_v8_pub`를 기반으로 만든 별도 저장소입니다. 원본 저장소는 수정하지 않습니다.

기존 분산 URL 정찰·httpx·엑셀 파이프라인에 **로컬 증거 기반 검증 모듈 `bounty_assist`**를 추가했습니다.

수집 URL만으로 취약점을 확정하지 않습니다. 실제 요청·응답, 계정 신원, 객체 소유 관계와 대조 요청을 함께 사용합니다.

## 추가된 흐름

```text
기존 GitHub Actions 정찰 → 암호화 보고서의 bounty_seed.jsonl
                                      ↓ 로컬 가져오기
URL TXT / httpx JSONL / HAR → 기능별 묶음 → Plus 로그인 Codex CLI
                                            ↓ 구조화된 테스트 계획
                                  로컬 재실행 · 반복 · 대조
                                            ↓ 결과 피드백
                               한국어 HTML + JSON 보고서
```

- 수집 도구의 `uro` 처리 전 URL도 보존합니다.
- 전체 경로와 요청 구조로 기능을 묶고, 객체 ID·계정·소유자별 요청과 캡처를 보존합니다.
- Codex가 후속 검증을 선택하며, 로컬 실행기는 대상·계정·입력 위치와 예산을 검사합니다.
- 권한 테스트는 계정 신원 확인, 소유자/다른 계정의 각 2회 요청, 음성 대조 2회로 후보를 판단합니다.
- 무해한 입력 반사와 테스트/대조 값에 따른 반복 응답 차이를 검사합니다.
- 업로드·SSRF·브라우저 XSS·다단계 업무 로직은 현재 실행기에서 **수동 검증 계획**으로 기록합니다.
- SQLite에 진행 상태와 예산을 저장해 같은 작업 폴더에서 남은 그룹을 재개합니다.
- 입력 크기와 누적 모델 토큰을 제한하고 사용량·미확인 호출·남은 그룹을 보고서에 표시합니다.
- 기본 추론은 `low`입니다. `adaptive_reasoning: true`일 때 권한 후보·일관된 응답 차이만 `medium`으로 검토합니다.
- Gemini의 URL 기반 확률 순위 기능은 기본 비활성화했습니다. 필요할 때 `ENABLE_LEGACY_GEMINI=1`과 기존 API 키로 사용할 수 있습니다.

## 시작하기

새 모듈은 Python 3.10 이상에서 표준 라이브러리만 사용합니다. 기존 정찰 도구와 엑셀 모듈의 의존성은 기존과 같습니다.

공식 Codex CLI를 설치하고 **ChatGPT 구독 계정**으로 로그인합니다.

```bash
npm install -g @openai/codex
codex login
codex login status
```

이 연결은 Codex CLI가 관리하는 구독 인증을 사용합니다. ChatGPT 쿠키를 추출하거나 비공개 API를 직접 호출하지 않습니다. API 키 인증은 이 모듈에서 거부하며 Plus 사용 한도는 그대로 적용됩니다.

먼저 네트워크 없이 URL 또는 보고서의 시드 파일을 가져옵니다.

```bash
python -m bounty_assist import reports/bounty_seed.jsonl
# 일반 URL TXT 또는 httpx JSONL도 가능
python -m bounty_assist import urls.txt
python -m bounty_assist inventory --output inventory.json
```

요청 본문과 로그인한 기능은 HAR로 추가합니다. 같은 계정의 모든 캡처에 같은 계정 이름을 사용하세요.

```bash
python -m bounty_assist import user_a.har --session user_a --owner user-a
python -m bounty_assist import user_b.har --session user_b --owner user-b
```

```bash
cp config.bounty.example.json config.local.json
```

`config.local.json`의 도메인·계정 신원 확인 값·권한 정책을 실제 프로그램에 맞게 수정합니다. **예제 계정과 `/api/me`는 실제 서비스 설정이 아닙니다.** 쿠키는 파일에 쓰지 않고 환경 변수로 공급합니다.

```bash
export BOUNTY_COOKIE_A='실제 A 계정 Cookie 헤더 값'
export BOUNTY_COOKIE_B='실제 B 계정 Cookie 헤더 값'
python -m bounty_assist run --config config.local.json
```

결과는 `reports/bounty_report.html`과 같은 이름의 JSON에 생성됩니다. HTML 하나에서 결과 검색·필터·증거 상세·전체 요청 목록을 볼 수 있습니다.

상세 설정과 판정 조건은 [한국어 사용 설명서](docs/bounty_assist_ko.md)를 참고하세요.

## Windows 실행

PowerShell에서 저장소 폴더로 이동한 뒤 실행합니다. Python 3.10 이상과 Node.js LTS가 필요합니다.

```powershell
# 공식 CLI 설치·본인 PC 로그인·대상 요청 없이 실제 GPT 호출 확인
powershell -NoProfile -ExecutionPolicy Bypass -File .\scripts\windows_start.ps1 -Mode Check -InstallCodex -Login
# 실제 GPT로 로컬 테스트 서버의 반복 진단 검증
powershell -NoProfile -ExecutionPolicy Bypass -File .\scripts\windows_start.ps1 -Mode LiveLab
```

`ExecutionPolicy Bypass`는 해당 PowerShell 프로세스에만 적용되며 시스템 정책을 변경하지 않습니다. 모의 데모는 `-Mode Demo`입니다. 실제 대상 설정을 완료한 다음 `-Mode Scan -Config config.local.json -Urls urls.txt`로 실행합니다. 쿠키 환경 변수는 해당 PowerShell 창에 설정하세요. 상세한 준비와 오류 대응은 [Windows 설명서](docs/windows_ko.md)를 참고하세요.

## 테스트와 로컬 데모

```bash
python -m unittest discover -s tests -v
python examples/demo_bounty.py
```

데모는 `127.0.0.1`에 일시적인 테스트 서버를 열어 권한 검증이 빠진 API와 조치된 API를 비교하고 `demo-output/bounty_demo.html`을 만듭니다. **데모 계획기는 GPT가 아니며 Plus 사용량을 쓰지 않습니다.** 실제 GPT 호출 성공과 탐지율은 별도의 로그인된 환경·평가 데이터로 확인해야 합니다.

## 현재 지원 범위

| 기능 | 상태 |
|---|---|
| URL TXT / httpx JSONL / HAR 가져오기 | 구현 |
| 기능별 표본 분석과 모든 원본 요청 보존 | 구현 |
| 공식 Codex CLI + Plus 구독 인증 연결 | 구현; 현재 작업 환경의 실제 모델 호출은 타임아웃으로 미검증 |
| 계정별 읽기 권한·정책 기반 객체 접근 검증 | 구현 |
| query / JSON / form / 단일 path 값 변경 | 구현 |
| 반복 응답 차이·무해한 입력 반사 | 구현, 취약점 확정 아님 |
| 요청·AI 예산, 속도 제한, 실패 저장·재개 | 구현 |
| multipart 업로드, CSRF 갱신, SOAP 전용 변경, 브라우저 XSS, OAST, 다단계 업무 로직 | 수동 계획; 전용 실행기는 후속 개발 필요 |

기본 실행 메서드는 GET/HEAD입니다. POST 등은 프로그램 규칙과 기능의 부작용을 확인한 뒤 `allowed_methods`에 직접 추가하세요. 리다이렉트는 따라가지 않습니다. 원본 HAR·응답·로컬 상태에는 민감 정보가 있을 수 있으므로 Git에 올리지 마세요.
