# Windows에서 실제 Plus 연결 확인

## 준비

Python 3.10 이상(Python launcher 포함), Node.js LTS, Git을 설치합니다. PowerShell을 열고 아래를 실행합니다.

```powershell
git clone https://github.com/ohjun1998/passive_scan_with_llm.git
Set-Location passive_scan_with_llm
# 이미 내려받았다면 해당 폴더에서 git pull
powershell -NoProfile -ExecutionPolicy Bypass -File .\scripts\windows_start.ps1 -Mode Check -InstallCodex -Login
```

공식 Codex 로그인에서 본인의 Plus 계정을 선택합니다. 이 과정은 사용자 PC에서 진행하며 다른 컴퓨터의 로그인은 옮겨지지 않습니다. 위 명령은 CLI 설치, 로그인, 지원 옵션 확인, 실제 모델 1회 호출까지 수행합니다. 검사 대상 웹사이트로 요청하지 않습니다. 모델 호출에는 구독 사용량이 적용됩니다.

`live_model_success: true`와 `MODEL_CALL_OK`가 표시되면 연결이 확인된 것입니다. 로그인 상태가 ChatGPT로 표시되더라도 모델 호출은 별도로 실패할 수 있습니다. `ExecutionPolicy Bypass`는 해당 프로세스에만 적용됩니다.

## 실제 모델로 로컬 진단 평가

```powershell
py -3 -m unittest discover -s tests -v
powershell -NoProfile -ExecutionPolicy Bypass -File .\scripts\windows_start.ps1 -Mode LiveLab
```

`127.0.0.1`의 일시적인 테스트 서버에만 HTTP 요청합니다. 테스트용 A/B 계정과 객체·권한 정책을 자동으로 준비하고 실제 GPT가 후속 검사 계획을 작성합니다. 결과는 `live-output\bounty_demo.html`과 JSON에 생성됩니다. 매 실행은 새 작업 폴더를 사용하며 기본 `low`, AI 최대 4회, 토큰 중단 기준 20000입니다. 토큰 기준은 마지막 호출에서 초과할 수 있습니다.

`auth_candidate`와 `not_reproduced`는 명시한 정책에 따른 로컬 실행기가 판정합니다. GPT가 모든 취약점을 독자적으로 발견했다는 평가가 아닙니다. 실제 모델 호출 횟수·사용량을 별도로 확인하세요. 모의 실행은 `-Mode Demo`이고 GPT를 호출하지 않습니다.

## 실제 URL 목록 실행

```powershell
Copy-Item config.bounty.example.json config.local.json
notepad config.local.json
```

허용된 정확한 origin, 계정별 origin, 실제 신원 확인 URL과 값, 권한 정책을 설정합니다. 예제 `app.example.com`과 사용자 이름을 그대로 사용하지 마세요. 인증이 필요 없는 URL 평가에서는 익명 계정만 설정할 수 있지만 인증·인가 검증 근거는 부족합니다.

쿠키를 코드나 공개 저장소에 넣지 않고 현재 PowerShell의 환경 변수에 공급합니다. 아래는 값을 화면에 입력하는 예제이며 입력 기록에 실제 쿠키를 남기지 않도록 `Read-Host -AsSecureString`을 사용합니다.

```powershell
function Set-PrivateSession([string]$Name) {
    $secure = Read-Host "$Name Cookie header" -AsSecureString
    $ptr = [Runtime.InteropServices.Marshal]::SecureStringToBSTR($secure)
    try {
        [Environment]::SetEnvironmentVariable($Name, [Runtime.InteropServices.Marshal]::PtrToStringBSTR($ptr), 'Process')
    } finally {
        [Runtime.InteropServices.Marshal]::ZeroFreeBSTR($ptr)
    }
}
Set-PrivateSession 'BOUNTY_COOKIE_A'
Set-PrivateSession 'BOUNTY_COOKIE_B'
# 선택: 계정별 업무 요청 HAR를 먼저 가져오기
py -3 -m bounty_assist import .\user_a.har --session user_a --owner user-a
py -3 -m bounty_assist import .\user_b.har --session user_b --owner user-b
py -3 -m bounty_assist inventory --output inventory.json
powershell -NoProfile -ExecutionPolicy Bypass -File .\scripts\windows_start.ps1 -Mode Scan -Config config.local.json -Urls urls.txt
```

스크립트는 설정·인증 점검 → URL 가져오기 → 계획/검사/피드백 → 보고서 열기를 실행합니다. 멈춘 경우 같은 명령으로 남은 그룹을 재개합니다. 종료 코드 2는 예산·그룹 제한·대상 백오프에 따른 중단입니다. 보고서와 상태는 남습니다. 실행 중 다른 프로세스에서 같은 작업 폴더를 사용하지 마세요.

## 사용량과 오류

```powershell
py -3 -m bounty_assist usage
py -3 -m bounty_assist --workspace .bounty-work-check usage
# 계정의 실제 사용량을 확인한 후에만 미확인 호출을 인정
py -3 -m bounty_assist --workspace .bounty-work-check usage --acknowledge-unknown
```

| 상황 | 확인 사항 |
|---|---|
| ChatGPT subscription login required / 인증 거부 | 현재 PC에서 `codex.cmd login`으로 다시 로그인 |
| CLI 옵션 미지원 | `npm.cmd install -g @openai/codex`로 업데이트 |
| 타임아웃·네트워크 정책 오류 | `auth.openai.com`, `chatgpt.com` 연결과 회사 네트워크 정책 확인 |
| 사용 한도 | 계정의 Codex 사용량 확인; 추가 호출로 해결되지 않음 |
| 환경 변수 누락 | 같은 PowerShell 창에서 해당 계정 헤더를 설정 |
| 그룹 제한 | 같은 작업 폴더로 재실행해 남은 그룹 처리 |
| 토큰/호출 예산 | 누적 사용량을 검토한 뒤 설정의 예산을 명시적으로 조정 |

현재 개발 환경에서는 실제 호출이 타임아웃으로 끝났습니다. 위 실사용 검증의 성공 결과와 Windows CI 결과를 구분해야 합니다. CI는 모의 CLI와 로컬 서버를 테스트하며 사용자 Plus 계정으로 호출하지 않습니다.

원본 HAR·응답·상태 DB는 사용자 계정의 비공개 폴더에 보관합니다. Windows 파일 ACL은 POSIX의 0600과 다르며 이 프로그램이 자동 설정하지 않습니다. 쿠키·토큰·로그인 코드는 공유하지 마세요.
