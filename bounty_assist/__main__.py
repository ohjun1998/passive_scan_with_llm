import argparse
import json
import sys
from pathlib import Path

from .data import Redactor, import_records
from .console import configure_console
from .engine import Engine
from .planner import CodexPlanner, DemoPlanner
from .report import render
from .runtime import Config
from .store import Store, private_json


def main(argv=None):
    configure_console()
    parser = argparse.ArgumentParser(description="passive-scan URL/HAR → Plus Codex → local evidence verification")
    parser.add_argument("--workspace", default=".bounty-work", help="Private local state; reuse to resume")
    sub = parser.add_subparsers(dest="command", required=True)
    imp = sub.add_parser("import", help="Import URL TXT, httpx JSONL or HAR (no network)")
    imp.add_argument("paths", nargs="+")
    imp.add_argument("--session", default="anonymous")
    imp.add_argument("--owner", default="")
    inventory = sub.add_parser("inventory", help="Export masked request IDs and groups (no network)")
    inventory.add_argument("--output", default="inventory.json")
    run = sub.add_parser("run", help="Execute bounded tests on explicitly configured origins")
    run.add_argument("--config", required=True)
    run.add_argument("--planner", choices=("codex", "none", "demo"), default="codex")
    run.add_argument("--report", default="reports/bounty_report.html")
    report = sub.add_parser("report", help="Regenerate masked report without sending requests")
    report.add_argument("--config", required=True)
    report.add_argument("--output", default="reports/bounty_report.html")
    doctor = sub.add_parser("doctor", help="Check CLI/login; --live makes one model call without target traffic")
    doctor.add_argument("--config")
    doctor.add_argument("--live", action="store_true")
    doctor.add_argument("--codex-executable", default="codex")
    usage = sub.add_parser("usage", help="Show cumulative local budgets, without network")
    usage.add_argument("--acknowledge-unknown", action="store_true",
                       help="Acknowledge unmetered calls after checking account usage; never resets known tokens")
    args = parser.parse_args(argv)
    store = Store(args.workspace)
    try:
        if args.command == "usage":
            unknown = store.count("model_usage_unknown_calls")
            if args.acknowledge_unknown:
                store.increment("model_usage_acknowledged_calls", unknown - store.count("model_usage_acknowledged_calls"))
            print(json.dumps({name: store.count(name) for name in (
                "http_requests", "ai_calls", "model_tokens", "model_input_tokens", "model_output_tokens",
                "model_usage_unknown_calls", "model_usage_acknowledged_calls")}, ensure_ascii=False))
            return 0
        if args.command == "doctor":
            data = json.loads(Path(args.config).read_text(encoding="utf-8-sig")) if args.config else {"origins": ["https://example.com"]}
            if args.codex_executable != "codex":
                data.setdefault("codex", {})["executable"] = args.codex_executable
            config = Config(data)
            planner = CodexPlanner(config)
            planner.check_capabilities()
            print("[+] CLI 옵션·ChatGPT 로그인 확인 완료. 검사 대상 HTTP 요청 없음.", flush=True)
            if args.live:
                if store.count("model_usage_unknown_calls") > store.count("model_usage_acknowledged_calls"):
                    raise RuntimeError("Codex usage is unknown; check usage and acknowledge before retrying")
                if store.count("model_tokens") >= config.data["max_model_tokens"] or not store.reserve("ai_calls", config.data["max_ai_calls"]):
                    raise RuntimeError("Codex local budget exhausted")
                import time
                key = "doctor-" + str(time.time_ns())
                store.call(key, "started", {"status": "started", "mode": "doctor", "is_live": True, "recorded_at": time.time()})
                try:
                    answer, tokens = planner.plan({"requests": [], "sessions": [{"name": "anonymous", "has_identity_check": False}],
                                                  "policies": [], "previous_results": [],
                                                  "instruction": "No requests exist. Return an empty plans array and notes=MODEL_CALL_OK."})
                except Exception:
                    store.increment("model_usage_unknown_calls", 1)
                    store.call(key, "failed", {"status": "failed", "mode": "doctor", "recorded_at": time.time()})
                    raise
                # Count real usage, including failed schema validation after a successful call.
                store.record_model_usage(tokens, live=True)
                valid = not answer["plans"]
                store.call(key, "completed" if valid else "failed", {"status": "completed" if valid else "failed", "mode": "doctor", "usage": tokens,
                                               "answer": {"notes": "MODEL_CALL_OK", "plans": []}, "recorded_at": time.time()})
                if not valid:
                    raise RuntimeError("Codex live check returned unexpected plans; rejected")
                print(json.dumps({"live_model_success": True, "marker": "MODEL_CALL_OK", "usage": tokens}, ensure_ascii=False))
            return 0
        if args.command == "import":
            before = len(store.requests())
            for path in args.paths:
                for req, response in import_records(path, args.session, args.owner):
                    store.add(req, response)
            print(f"[+] {len(store.requests()) - before}개 요청 추가; 전체 {len(store.requests())}개")
        elif args.command == "inventory":
            redactor = Redactor(store.salt)
            records = [redactor.request(r) for r in store.requests()]
            private_json(args.output, records)
            print(f"[+] 요청 {len(records)}개: {args.output}")
        else:
            config = Config(json.loads(Path(args.config).read_text(encoding="utf-8-sig")))
            planner = None
            if args.command == "run":
                if args.planner == "codex":
                    # Authenticate before sending any assessment traffic.
                    planner = CodexPlanner(config)
                elif args.planner == "demo":
                    print("[DEMO] 실제 GPT 호출 없음 — 오프라인 모의 계획기")
                    planner = DemoPlanner()
            engine = Engine(store, config, planner)
            if args.command == "run":
                try:
                    status = engine.run()
                    print(json.dumps(status, ensure_ascii=False))
                finally:
                    render(engine, args.report)
                print(f"[+] 보고서: {args.report}")
                return 2 if status["stopped"] else 0
            render(engine, args.output)
            print(f"[+] 보고서: {args.output}")
        return 0
    except (ValueError, KeyError, OSError, RuntimeError) as exc:
        # Avoid echoing raw session material through exceptions.
        print(f"[-] {type(exc).__name__}: 설정·입력·Codex 로그인/한도를 확인하세요. 진행 상태는 보존됩니다.", file=sys.stderr)
        if str(exc).startswith(("Codex", "ChatGPT", "origins", "Policy", "Session")):
            print(str(exc), file=sys.stderr)
        return 1
    finally:
        store.db.close()


if __name__ == "__main__":
    raise SystemExit(main())
