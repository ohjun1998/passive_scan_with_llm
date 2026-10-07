#!/bin/bash
mkdir -p results
GROUP_SUFFIX=$1

split -d -n l/4 targets.txt targets_group
TARGET_FILE="targets_group${GROUP_SUFFIX}"

scan_wb() {
    local domain=$(echo "$1" | xargs)
    [[ -z "$domain" || "$domain" =~ ^# ]] && return

    echo "[+] [$domain] [Waybackurls Matrix Worker] Fetching URLs..."
    echo "$domain" | waybackurls > "results/${domain}_waybackurls.txt" 2>/dev/null
    sort -u "results/${domain}_waybackurls.txt" -o "results/${domain}_waybackurls.txt"
}

export -f scan_wb
echo "[*] Starting Dynamic Matrix waybackurls Scanner for $TARGET_FILE..."
xargs -P 10 -n 1 -a "$TARGET_FILE" -I {} bash -c 'scan_wb "{}"'

rm -f targets_group*
