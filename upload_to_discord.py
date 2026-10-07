import requests
import os

def send_discord_notification():
    webhook_url = os.environ.get('DISCORD_WEBHOOK_URL')
    if not webhook_url:
        print("[-] DISCORD_WEBHOOK_URL 환경 변수가 설정되지 않았습니다.")
        return

    new_subs = []
    # 위 txt_to_excel.py에서 생성한 신규 서브도메인 목록 텍스트 파일 읽기
    if os.path.exists('reports/new_subdomains.txt'):
        with open('reports/new_subdomains.txt', 'r', encoding='utf-8') as f:
            new_subs = [line.strip() for line in f if line.strip()]

    if new_subs:
        # 메시지가 너무 길어지는 것을 방지하기 위해 최대 15개까지만 노출
        sub_text = "\n".join([f"🔹 {s}" for s in new_subs[:15]])
        if len(new_subs) > 15:
            sub_text += f"\n\n... 외 {len(new_subs)-15}개 더 발견됨"
        
        embed_color = 15158332 # 경고/알림을 의미하는 Red/Orange 색상
        embed_title = "🚨 새로운 서브도메인 발견!"
        embed_desc = f"```\n{sub_text}\n```\n상세 내역과 취약점 분석 결과는 첨부된 **보안 엑셀 리포트**를 확인하세요."
    else:
        embed_color = 3066993 # 안전을 의미하는 Green 색상
        embed_title = "✅ 일일 정찰 보고서 완료"
        embed_desc = "이번 스캔에서는 새로 발견된 서브도메인이 없습니다."

    payload = {
        "content": "🚀 **Passive Reconnaissance 분산 스캔 엔진 가동 완료**",
        "embeds": [{
            "title": embed_title,
            "description": embed_desc,
            "color": embed_color
        }]
    }
    
    try:
        requests.post(webhook_url, json=payload)
        print("[+] 디스코드 알림 전송 완료")
    except Exception as e:
        print(f"[-] 디스코드 알림 전송 실패: {e}")

if __name__ == "__main__":
    send_discord_notification()
