"""Run ONLY a loopback lab; no Codex login or external assessment target needed."""
import json
import argparse
import os
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "tests"))

from bounty_assist.data import Request
from bounty_assist.engine import Engine
from bounty_assist.planner import CodexPlanner, DemoPlanner, PLAN_FIELDS
from bounty_assist.report import render
from bounty_assist.runtime import Config
from bounty_assist.store import Store
from lab import config_for, lab


def main():
    parser = argparse.ArgumentParser(description="Loopback-only lab; --live uses real Plus/Codex quota")
    parser.add_argument("--live", action="store_true", help="Use real Codex; no remote assessment targets")
    parser.add_argument("--codex-executable", default="codex")
    args = parser.parse_args()
    output = ROOT / ("live-output" if args.live else "demo-output")
    # A unique workspace on each run avoids reusing an old server port/budget.
    import tempfile
    output.mkdir(exist_ok=True)
    workspace = tempfile.mkdtemp(prefix="lab-", dir=output)
    os.environ["LAB_COOKIE_A"] = "sid=lab-user-a"
    os.environ["LAB_COOKIE_B"] = "sid=lab-user-b"
    store = Store(workspace)
    try:
        with lab() as (base, server):
            config = config_for(base)
            config["max_ai_calls"] = 4
            config["max_model_tokens"] = 20000
            config["codex"] = {"executable": args.codex_executable, "reasoning_effort": "low", "timeout": 90}
            config["policies"] = []
            control = Request(base + "/api/orders/999")
            store.add(control)
            for number in (1, 2):
                req = Request(base + f"/api/orders/{number}", session="user_a", owner="user-a")
                store.add(req)
                config["policies"].append({"request_id": req.id, "owner_session": "user_a", "denied_sessions": ["user_b"],
                                           "control_request_id": control.id, "json_pointer": "/private", "equals": "lab-private-order"})
            echo = Request(base + "/echo?q=hello")
            store.add(echo)
            settings = Config(config)
            planner = CodexPlanner(settings) if args.live else DemoPlanner()
            if args.live:
                planner.check_capabilities()
            engine = Engine(store, settings, planner)
            try:
                status = engine.run()
            finally:
                render(engine, output / "bounty_demo.html")
            reflection = {k: "" for k in PLAN_FIELDS}
            reflection.update(request_id=echo.id, kind="reflection", session="anonymous", location="query", field="q",
                              hypothesis="[DEMO] 무해한 표식 반사", expected_evidence="브라우저 실행은 별도 확인")
            if not args.live:
                engine.execute(reflection)
            report = render(engine, output / "bounty_demo.html")
            findings = [r for r in store.all("results") if r.get("kind") != "observation"]
            successful = sum(c.get("status") == "completed" for c in store.all("calls"))
            print(json.dumps({"mode": "LIVE CODEX" if args.live else "DEMO; no real GPT calls", "status": status,
                              "completed_model_calls": successful if args.live else 0,
                              "completed_planner_rounds": successful, "model_tokens": store.count("model_tokens"),
                              "states": [r["state"] for r in findings], "http_requests": len(server.hits), "report": str(report)}, ensure_ascii=False))
            if args.live and not successful:
                return 2
            return 2 if status["stopped"] else 0
    finally:
        store.db.close()


if __name__ == "__main__":
    raise SystemExit(main())
