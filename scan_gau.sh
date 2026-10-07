#!/bin/bash
mkdir -p results
GROUP_SUFFIX=$1

split -d -n l/4 targets.txt targets_group
TARGET_FILE="targets_group${GROUP_SUFFIX}"

scan_gau() {
    local domain=$(echo "$1" | xargs)
    [[ -z "$domain" || "$domain" =~ ^# ]] && return

    echo "[+] [$domain] [gau Matrix Worker] Fetching URLs..."
    echo "$domain" | gau > "results/${domain}_gau.txt" 2>/dev/null
    sort -u "results/${domain}_gau.txt" -o "results/${domain}_gau.txt"
}

export -f scan_gau
echo "[*] Starting Dynamic Matrix gau Scanner for $TARGET_FILE..."
xargs -P 10 -n 1 -a "$TARGET_FILE" -I {} bash -c 'scan_gau "{}"'

rm -f targets_group*
