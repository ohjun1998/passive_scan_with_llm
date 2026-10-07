#!/bin/bash

# $1 인자가 없으면 기본값(00) 할당
GROUP=${1:-"00"}
TARGETS_FILE="targets.txt"

if [ ! -f "$TARGETS_FILE" ]; then
  echo "[-] $TARGETS_FILE 파일이 존재하지 않습니다."
  exit 1
fi

mkdir -p results
touch global_js_db.txt

echo "==================================================================="
echo "🚀 [Node-$GROUP] 정찰 파이프라인 가동 (MapReduce 기반 분산 스캔)"
echo "==================================================================="

# 1. 태그(SAFE_DOMAIN)를 기준으로 타겟들을 분리 저장 (동시 파일 접근 충돌 방지)
awk -F':' '{print $2 > "results/"$1"_all_targets.txt"}' $TARGETS_FILE

for TARGET_FILE in results/*_all_targets.txt; do
  [ -e "$TARGET_FILE" ] || continue
  
  BASENAME=$(basename "$TARGET_FILE")
  SAFE_DOMAIN=${BASENAME%_all_targets.txt}
  
  echo "=================================================="
  echo "🎯 [Target: $SAFE_DOMAIN] 할당된 서브도메인 병렬 스캔 가동"
  echo "=================================================="

  # ---------------------------------------------------------
  # 2. Waybackurls (과거 아카이브 URL 병렬 추출)
  # ---------------------------------------------------------
  (
    echo "  [+] 🏛️ [Waybackurls] 병렬 추출 중..."
    cat "$TARGET_FILE" | waybackurls | tee "results/${SAFE_DOMAIN}_waybackurls_raw_${GROUP}.txt" | uro > "results/${SAFE_DOMAIN}_waybackurls_${GROUP}.txt" 2>/dev/null || true
  ) &

  # ---------------------------------------------------------
  # 3. GAU (외부 위협 인텔리전스 기반)
  # ---------------------------------------------------------
  (
    echo "  [+] 🌐 [GAU] 위협 인텔리전스 추출 중..."
    cat "$TARGET_FILE" | gau --threads 5 | tee "results/${SAFE_DOMAIN}_gau_raw_${GROUP}.txt" | uro > "results/${SAFE_DOMAIN}_gau_${GROUP}.txt" 2>/dev/null || true
  ) &

  # ---------------------------------------------------------
  # 4. Katana (스텔스 크롤링 - 확장된 타겟 리스트 활용)
  # ---------------------------------------------------------
  (
    echo "  [+] 🕷️ [Katana] 스텔스 크롤링 중..."
    katana -list "$TARGET_FILE" -d 2 -c 5 -rl 50 -jc -silent | tee "results/${SAFE_DOMAIN}_katana_raw_${GROUP}.txt" | uro > "results/${SAFE_DOMAIN}_katana_${GROUP}.txt" 2>/dev/null || true
  ) &

  # ---------------------------------------------------------
  # ⚡ 3개의 스캐너가 모두 끝날 때까지 대기
  # ---------------------------------------------------------
  wait
  echo "  [*] ✅ 해당 서브도메인 묶음의 딥 스캔 완료!"

  # ---------------------------------------------------------
  # 5. JS 파일 추출 및 스마트 다운로드 (방어 로직 강화)
  # ---------------------------------------------------------
  echo "  [+] ⚙️ 수집된 전체 데이터에서 JavaScript(JS) 타겟 추출 중..."
  cat "results/${SAFE_DOMAIN}_"*"_${GROUP}.txt" 2>/dev/null | grep -iE '\.js($|\?)' | awk -F '?' '{print $1}' | sort -u > "results/${SAFE_DOMAIN}_js_targets.txt" || true
  JS_TOTAL=$(wc -l < "results/${SAFE_DOMAIN}_js_targets.txt" 2>/dev/null || echo 0)

  if [ "$JS_TOTAL" -gt 0 ]; then
    echo "  [+] 💡 총 ${JS_TOTAL}개의 자바스크립트(JS) 소스 경로를 식별했습니다."

    # 이전에 분석한 JS 파일 제외 (스마트 필터링)
    grep -v -F -f global_js_db.txt "results/${SAFE_DOMAIN}_js_targets.txt" > "results/${SAFE_DOMAIN}_js_new.txt" 2>/dev/null || cat "results/${SAFE_DOMAIN}_js_targets.txt" > "results/${SAFE_DOMAIN}_js_new.txt"
    JS_NEW=$(wc -l < "results/${SAFE_DOMAIN}_js_new.txt" 2>/dev/null || echo 0)

    echo "  [!] 🛡️ [중복 방지] 과거에 분석 완료된 파일 제외: ${JS_NEW}개의 신규 JS만 남았습니다."

    if [ "$JS_NEW" -gt 0 ]; then
      head -n 1000 "results/${SAFE_DOMAIN}_js_new.txt" > "results/${SAFE_DOMAIN}_js_final.txt"
      JS_FINAL=$(wc -l < "results/${SAFE_DOMAIN}_js_final.txt" 2>/dev/null || echo 0)

      echo "  [!] 🛡️ [용량 보호] 디스크 과부하 및 타임아웃 방지를 위해 최대 ${JS_FINAL}개까지만 다운로드를 진행합니다."
      echo "  [+] 📥 JS 다운로드 병렬(10 Thread) 가동 중..."

      mkdir -p "results/${SAFE_DOMAIN}_js_files_${GROUP}"
      
      # 💡 xargs 내부 curl 에러로 인한 Exit Code 123 방지를 위해 || true 처리 추가
      cat "results/${SAFE_DOMAIN}_js_final.txt" | xargs -I {} -P 10 sh -c '
        url="{}"
        filename=$(basename "$url")
        curl -s -f -m 3 --create-dirs -o "results/'${SAFE_DOMAIN}'_js_files_'${GROUP}'/$filename" "$url" && echo "$url" >> global_js_db.txt || true
      ' || true

      DOWNLOADED=$(ls -1q "results/${SAFE_DOMAIN}_js_files_${GROUP}" 2>/dev/null | wc -l)
      echo "  [+] ✅ 다운로드 성공: 총 ${DOWNLOADED} 개 확보"
    else
      echo "  [+] ✅ 다운로드할 신규 JS 파일이 없습니다. (모두 이미 분석됨)"
    fi
  else
    echo "  [-] 💡 식별된 JS 소스 경로가 없습니다."
  fi

done

echo "==================================================================="
echo "🏁 [Node-$GROUP] 도메인 수집 프로세스 종료"
echo "==================================================================="
