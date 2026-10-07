#!/usr/bin/env python3
import os
import glob
import re
import random
import posixpath
from urllib.parse import urlparse, parse_qsl
from bounty_assist.data import path_template
from bounty_assist.seed import write_seed

def make_absolute(url, domain):
    if url.startswith('http://') or url.startswith('https://'): return url
    elif url.startswith('//'): return f"https:{url}"
    elif url.startswith('/'): return f"https://{domain}{url}"
    else: return f"https://{domain}/{url}"

def get_safe_domain(target):
    return "wild_" + target[2:] if target.startswith('*.') else target

def normalize_dynamic_path(path):
    return path_template(path)

def run_mixer():
    print("[+] 글로벌 셔플 엔진 가동 (과거 DB 통합 및 Httpx 재검증 준비)...")
    if not os.path.exists('targets.txt'): return
    
    with open('targets.txt', 'r') as f:
        targets = [line.strip() for line in f if line.strip()]

    target_map = {get_safe_domain(t): t for t in targets}

    js_url_converter = {}
    for mf in glob.glob('results/*_js_mapping.txt'):
        try:
            with open(mf, 'r', encoding='utf-8', errors='ignore') as f:
                for line in f:
                    if '\t' in line:
                        s, o = line.strip().split('\t', 1)
                        js_url_converter[s] = o
        except: pass

    all_urls = set()
    txt_files = glob.glob('results/**/*.*', recursive=True) + glob.glob('results/*.*')
    
    for file_path in txt_files:
        if not os.path.isfile(file_path): continue
        filename = os.path.basename(file_path).lower()
        match = re.match(r'^(.*)_(linkfinder|trufflehog|gau|waybackurls|katana)(?:_raw)?(?:_[0-9]{2})?\.txt$', filename)
        if not match: continue
        
        safe_domain = match.group(1)
        if safe_domain not in target_map: continue
        
        raw_target = target_map[safe_domain]
        is_wildcard = raw_target.startswith('*.')
        base_domain = raw_target[2:] if is_wildcard else raw_target

        try:
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                for line in f:
                    line_str = line.strip()
                    if not line_str or line_str.startswith('#'): continue
                    line_str = re.sub(r'[\x00-\x08\x0b\x0c\x0e-\x1f\x7f-\x9f]', '', line_str)
                    if not line_str: continue

                    if '\t' in line_str: raw_url = line_str.split('\t', 1)[1]
                    else: raw_url = line_str

                    abs_url = make_absolute(raw_url, base_domain)
                    parsed_netloc = urlparse(abs_url).netloc.split(':')[0]
                    
                    if is_wildcard:
                        if not (parsed_netloc == base_domain or parsed_netloc.endswith('.' + base_domain)):
                            continue
                    else:
                        if parsed_netloc != base_domain:
                            continue
                            
                    all_urls.add(abs_url)
        except: pass

    # 💡 [핵심 추가] 이전 스캔에서 찾아둔 과거 URL 텍스트 DB를 통째로 쏟아 붓습니다! (오늘 Httpx가 상태를 재검사하게 됨)
    prev_db_path = 'previous_report/master_url_db.txt'
    if os.path.exists(prev_db_path):
        try:
            print("[*] 이전 스캔 텍스트 DB를 글로벌 믹서에 합류시킵니다 (Httpx 전체 재검사)...")
            with open(prev_db_path, 'r', encoding='utf-8') as f:
                for line in f:
                    url = line.strip()
                    host = urlparse(url).hostname
                    if url and host and any(host == t.removeprefix('*.') or
                            (t.startswith('*.') and host.endswith('.' + t[2:])) for t in targets):
                        all_urls.add(url)
        except Exception as e:
            print(f"[-] 텍스트 DB 합류 실패: {e}")

    junk_exts = ('.png', '.jpg', '.jpeg', '.gif', '.svg', '.css', '.woff', '.woff2', '.ico', '.eot', '.ttf', '.mp4')
    blacklist_words = ['logout', 'signout', 'delete', 'remove', 'revoke', 'destroy']
    
    valid_targets = []
    signature_counts = {}
    
    # Preserve ALL discovered variants for AI/authorization analysis, before probe sampling.
    write_seed(all_urls, 'chunks/bounty_seed.jsonl')
    for u in sorted(all_urls):
        parsed = urlparse(u)
        
        if parsed.path.lower().endswith(junk_exts): continue
        url_lower = u.lower()
        if any(b in url_lower for b in blacklist_words): continue
            
        query_keys = tuple(sorted([k for k, v in parse_qsl(parsed.query, keep_blank_values=True)]))
        normalized_path = normalize_dynamic_path(parsed.path)
        path_dir = posixpath.dirname(normalized_path)
        path_ext = posixpath.splitext(normalized_path)[1]
        
        signature = (parsed.netloc, normalized_path, query_keys)
        
        if signature_counts.get(signature, 0) >= 5: continue
            
        signature_counts[signature] = signature_counts.get(signature, 0) + 1
        valid_targets.append(u)

    random.shuffle(valid_targets)
    print(f"[+] 노이즈 완전 제거 및 글로벌 셔플 완료! 최종 점검 대상(과거+오늘): 총 {len(valid_targets)} 개")

    os.makedirs('chunks', exist_ok=True)
    num_chunks = 20
    
    if len(valid_targets) == 0:
        for i in range(num_chunks): open(f'chunks/chunk_{i:02d}.txt', 'w').close()
        return

    chunk_size = (len(valid_targets) + num_chunks - 1) // num_chunks
    for i in range(num_chunks):
        chunk_data = valid_targets[i*chunk_size : (i+1)*chunk_size]
        with open(f'chunks/chunk_{i:02d}.txt', 'w') as f:
            for url in chunk_data: f.write(url + '\n')
        print(f"  -> 노드 {i:02d} 배정 완료: {len(chunk_data)} 개의 타겟 할당")

if __name__ == '__main__':
    run_mixer()
