#!/bin/bash
GROUP=${1:-"00"}

# 원본 targets.txt를 20분할하여 자신에게 할당된 타겟만 담당
split -d -n l/20 targets.txt split_targets_
MY_TARGET="split_targets_${GROUP}"

mkdir -p results
touch results/discovered_subdomains_${GROUP}.txt

if [ ! -f "$MY_TARGET" ]; then
    exit 0
fi

echo "🚀 [Node-$GROUP] 서브도메인 탐색 전담(Map) 페이즈 가동..."

for DOMAIN in $(cat $MY_TARGET); do
    if [[ "$DOMAIN" == \*\.* ]]; then
        SAFE_DOMAIN="wild_"$(echo "$DOMAIN" | sed 's/^\*\.//')
        BASE_DOMAIN=$(echo "$DOMAIN" | sed 's/^\*\.//')
        echo "[+] [Subfinder] 와일드카드 타겟 탐색: $BASE_DOMAIN"
        # 나중에 파일 병합 시 충돌을 막기 위해 'SAFE_DOMAIN:SUBDOMAIN' 형태로 태그를 달아 출력
        subfinder -d $BASE_DOMAIN -all -silent | awk -v sd="$SAFE_DOMAIN" '{print sd":"$0}' >> results/discovered_subdomains_${GROUP}.txt
        echo "${SAFE_DOMAIN}:${BASE_DOMAIN}" >> results/discovered_subdomains_${GROUP}.txt
    else
        SAFE_DOMAIN="$DOMAIN"
        echo "${SAFE_DOMAIN}:${DOMAIN}" >> results/discovered_subdomains_${GROUP}.txt
    fi
done

sort -u results/discovered_subdomains_${GROUP}.txt -o results/discovered_subdomains_${GROUP}.txt
