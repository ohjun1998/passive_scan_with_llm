#!/usr/bin/env python3
import os
import glob
import random

def mix_subdomains():
    print("[*] Phase 2: 서브도메인 글로벌 믹서 (Shuffle) 가동...")
    all_subs = set()
    
    # 20개 노드에서 발굴한 서브도메인 취합
    for f in glob.glob('results/discovered_subdomains_*.txt'):
        with open(f, 'r', encoding='utf-8') as file:
            for line in file:
                line = line.strip()
                if line:
                    all_subs.add(line)
    
    subs_list = list(all_subs)
    random.shuffle(subs_list) # 특정 도메인에 부하가 쏠리지 않도록 셔플
    
    num_chunks = 20
    os.makedirs('balanced_targets', exist_ok=True)
    
    if not subs_list:
        for i in range(num_chunks):
            open(f'balanced_targets/targets_{i:02d}.txt', 'w').close()
        return

    # 완벽하게 20등분하여 2차 워커들에게 배분할 준비
    chunk_size = (len(subs_list) + num_chunks - 1) // num_chunks
    for i in range(num_chunks):
        chunk = subs_list[i*chunk_size : (i+1)*chunk_size]
        with open(f'balanced_targets/targets_{i:02d}.txt', 'w', encoding='utf-8') as out_f:
            for sub in chunk:
                out_f.write(sub + '\n')
    
    print(f"[+] 총 {len(subs_list)}개의 서브도메인 중복 제거 및 20분할 배분 완료!")

if __name__ == '__main__':
    mix_subdomains()
