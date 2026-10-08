import html
import json
import os
from collections import Counter
from pathlib import Path

from .store import private_json


LABELS = {"auth_candidate": "권한 우회 후보", "reflection_signal": "입력 반사", "differential_signal": "응답 차이",
          "manual_required": "수동 검증", "inconclusive": "미확인", "not_reproduced": "재현 안 됨", "rejected": "계획 거부"}


def export(engine, path):
    results = [engine.safe_result(r) for r in engine.store.all("results")]
    requests = [engine.redactor.request(r) for r in engine.requests.values()]
    # Preserve operational session references (safe_result only masks actual headers/bodies).
    payload = {"version": 1, "requests": requests, "results": results,
               "plans": engine.store.all("plans"), "calls": engine.store.all("calls"),
               "coverage": {"imported_requests": len(requests), "observations": sum(r.get("kind") == "observation" for r in results),
                            "http_requests": engine.store.count("http_requests"), "ai_calls": engine.store.count("ai_calls"),
                            "model_tokens": engine.store.count("model_tokens"),
                            "max_model_tokens": engine.config.data["max_model_tokens"],
                            "model_usage_unknown_calls": engine.store.count("model_usage_unknown_calls"),
                            "max_requests": engine.config.data["max_requests"], "max_ai_calls": engine.config.data["max_ai_calls"]}}
    payload["demo"] = any("Offline demo" in c.get("answer", {}).get("notes", "") for c in payload["calls"])
    last_run = engine.store.db.execute("SELECT value FROM settings WHERE name='last_run'").fetchone()
    payload["last_run"] = json.loads(last_run[0]) if last_run else None
    payload["model_usage"] = {k: engine.store.count("model_" + k)
                              for k in ("input_tokens", "output_tokens", "cached_input_tokens", "reasoning_output_tokens")}
    private_json(path, payload)
    return payload


def render(engine, destination):
    destination = Path(destination)
    payload = export(engine, destination.with_suffix(".json"))
    findings = [r for r in payload["results"] if r.get("kind") != "observation"]
    counts = Counter(r.get("state", "inconclusive") for r in findings)
    esc = lambda x: html.escape(str(x), quote=True)
    request_map = {r["id"]: r for r in payload["requests"]}
    cards = "".join(f'<div class="card"><strong>{count}</strong><span>{esc(LABELS.get(state, state))}</span></div>'
                    for state, count in sorted(counts.items()))
    rows = []
    for index, finding in enumerate(findings, 1):
        state = finding.get("state", "inconclusive")
        req = request_map.get(finding.get("request_id"), {})
        summary = finding.get("hypothesis", finding.get("reason", ""))
        detail = json.dumps(finding, ensure_ascii=False, indent=2)
        rows.append(f'<article class="finding" data-state="{esc(state)}"><div class="row"><span class="badge">{esc(LABELS.get(state, state))}</span>'
                    f'<b>#{index} {esc(summary)}</b></div><p class="url">{esc(req.get("method", ""))} {esc(req.get("url", ""))}</p>'
                    f'<p>{esc(finding.get("reason", ""))}</p><details><summary>요청 변경 · 계정 · 반복 결과 · 대조 증거</summary><pre>{esc(detail)}</pre></details></article>')
    inventory_rows = "".join(f'<tr><td>{esc(r["id"])}</td><td>{esc(r["method"])}</td><td>{esc(r["session"])}</td>'
                             f'<td>{esc(r["owner"])}</td><td>{esc(r["url"])}</td></tr>' for r in payload["requests"])
    coverage = payload["coverage"]
    document = '''<!doctype html><html lang="ko"><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<meta http-equiv="Content-Security-Policy" content="default-src 'none'; style-src 'unsafe-inline'; script-src 'unsafe-inline'; base-uri 'none'; form-action 'none'">
<title>Passive Scan · 검증 보고서</title><style>
*{box-sizing:border-box}body{margin:0;background:#f3f5fa;color:#172239;font:15px/1.7 system-ui,sans-serif}
main{max-width:1120px;margin:auto;padding:32px 20px}header{background:#142842;color:white;padding:30px;border-radius:18px}
h1{margin:0;font-size:28px}header p{color:#c9d8ef}h2{font-size:21px;margin-top:30px}.cards{display:flex;flex-wrap:wrap;gap:12px;margin:20px 0}
.card{background:white;border:1px solid #dbe2ef;border-radius:12px;min-width:135px;padding:15px}.card strong{display:block;font-size:27px}
.card span{color:#52647c}.finding{margin:14px 0;padding:22px;background:white;border:1px solid #dbe2ef;border-radius:12px}
.row{display:flex;gap:12px;align-items:start;flex-wrap:wrap}.badge{background:#edf1fa;border-radius:6px;padding:3px 9px;white-space:nowrap}
.url{overflow-wrap:anywhere;color:#52647c}details{border-top:1px solid #e5e9f2;padding-top:10px}summary{cursor:pointer;color:#245c99}
pre{white-space:pre-wrap;overflow-wrap:anywhere;font-size:12px;line-height:1.6;background:#f5f7fc;padding:15px;border-radius:8px}
input,select{padding:10px;border:1px solid #c5cede;border-radius:8px;font:inherit}input{width:min(100%,420px)}
.table-wrap{overflow:auto;background:white;border-radius:10px}table{border-collapse:collapse;min-width:700px;width:100%;font-size:12px}
th,td{text-align:left;padding:10px;border-bottom:1px solid #e5e9f2;vertical-align:top}td:last-child{overflow-wrap:anywhere;min-width:250px}
.note{color:#52647c}.empty{padding:24px;background:white;border-radius:12px}@media(max-width:600px){main{padding:16px 10px}header{padding:20px}h1{font-size:23px}}
</style><main><header><h1>Passive Scan · 증거 기반 검증</h1><p>계획 → 요청 재실행 → 대조 → 반복 재현</p><div>COVERAGE</div></header>
<p class="note">자동 판정은 보고서 후보입니다. 입력 반사는 XSS 확정이 아니며, 미확인·재현 안 됨은 안전하다는 뜻이 아닙니다. 계정 정책과 실제 영향을 최종 검토하세요.</p>
<section class="cards">CARDS</section><h2>검증 결과</h2><input id="search" placeholder="URL · 가설 · 계정 검색" aria-label="검색">
<select id="filter" aria-label="결과 필터"><option value="">모든 결과</option>OPTIONS</select><section id="findings">FINDINGS</section>
<h2>수집된 요청 전체</h2><p class="note">표본 분석에서 선택되지 않은 요청도 보존됩니다. 세부 증거는 같은 이름의 JSON 파일에서도 확인할 수 있습니다.</p>
<div class="table-wrap"><table><thead><tr><th>요청 ID</th><th>메서드</th><th>계정</th><th>소유자</th><th>URL</th></tr></thead><tbody>INVENTORY</tbody></table></div>
<script>const search=document.getElementById('search'),filter=document.getElementById('filter');function update(){document.querySelectorAll('.finding').forEach(el=>{el.hidden=!(el.textContent.toLowerCase().includes(search.value.toLowerCase())&&(!filter.value||el.dataset.state===filter.value))})}search.addEventListener('input',update);filter.addEventListener('change',update);</script></main></html>'''
    mode = ' · DEMO (실제 GPT 호출 없음)' if payload["demo"] else ''
    if payload["last_run"]:
        last = payload["last_run"]
        mode += f' · 그룹 {last["groups_processed"]}/{last["groups_total"]} · 남은 그룹 {last["groups_remaining"]}'
    replacements = {"COVERAGE": f'수집 요청 {coverage["imported_requests"]} · HTTP {coverage["http_requests"]}/{coverage["max_requests"]} · AI {coverage["ai_calls"]}/{coverage["max_ai_calls"]}{mode}',
                    "CARDS": cards + f'<div class="card"><strong>{coverage["model_tokens"]}</strong><span>누적 모델 토큰 · 기준 {coverage["max_model_tokens"]}</span></div>' + f'<p class="note">토큰 기준은 호출 후 확인하는 중단 기준입니다. 사용량 미확인 호출: {coverage["model_usage_unknown_calls"]}. Plus 잔여 한도를 뜻하지 않습니다.</p>',
                    "OPTIONS": "".join(f'<option value="{esc(s)}">{esc(LABELS.get(s,s))}</option>' for s in sorted(counts)),
                    "FINDINGS": "".join(rows) or '<p class="empty">검증 결과가 없습니다. 요청 목록을 가져온 뒤 run 명령을 실행하세요.</p>',
                    "INVENTORY": inventory_rows}
    # Replace tokens in the template only; never process tokens inside untrusted text.
    import re
    document = re.sub(r"COVERAGE|CARDS|OPTIONS|FINDINGS|INVENTORY", lambda m: replacements[m[0]], document)
    destination.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    fd = os.open(destination, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w", encoding="utf-8") as f:
        f.write(document)
    os.chmod(destination, 0o600)
    return destination
