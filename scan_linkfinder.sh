#!/bin/bash
GROUP_SUFFIX=$1
mkdir -p results

scan_jsluice() {
    local dir="$1"
    local group="$2"
    
    [ -d "$dir" ] || return
    
    local basename_dir=$(basename "$dir")
    local safe_domain=${basename_dir%_js_files_*}
    
    echo "[+] [${safe_domain}] [jsluice] 추출 시작..."
    rm -f "results/${safe_domain}_jsluice_raw_${group}.txt"
    touch "results/${safe_domain}_jsluice_raw_${group}.txt"

    for js_file in "$dir"/*.js; do
        [ -f "$js_file" ] || continue
        local fname=$(basename "$js_file")
        jsluice urls "$js_file" 2>/dev/null | jq -r --arg f "$fname" '.url | "\($f)\t\(.)"' >> "results/${safe_domain}_jsluice_raw_${group}.txt" || true
    done

    if [ -s "results/${safe_domain}_jsluice_raw_${group}.txt" ]; then
        sort -u "results/${safe_domain}_jsluice_raw_${group}.txt" > "results/${safe_domain}_linkfinder_${group}.txt"
    else
        echo "" > "results/${safe_domain}_linkfinder_${group}.txt"
    fi
    rm -f "results/${safe_domain}_jsluice_raw_${group}.txt"
}
export -f scan_jsluice

echo "[*] 오프라인 jsluice 분석 가동..."
for dir in results/*_js_files_${GROUP_SUFFIX}; do
    scan_jsluice "$dir" "$GROUP_SUFFIX" &
done
wait
