import argparse
import json
import sys
from pathlib import Path

from .data import Redactor, import_records
from .engine import Engine
from .planner import CodexPlanner, DemoPlanner
from .report import render
from .runtime import Config
from .store import Store, private_json


def main(argv=None):
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
    args = parser.parse_args(argv)
    store = Store(args.workspace)
    try:
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
            config = Config(json.loads(Path(args.config).read_text(encoding="utf-8")))
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
