"""Run ONLY a loopback lab; no Codex login or external assessment target needed."""
import json
import os
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "tests"))

from bounty_assist.data import Request
from bounty_assist.engine import Engine
from bounty_assist.planner import DemoPlanner, PLAN_FIELDS
from bounty_assist.report import render
from bounty_assist.runtime import Config
from bounty_assist.store import Store
from lab import config_for, lab


def main():
    output = ROOT / "demo-output"
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
            engine = Engine(store, Config(config), DemoPlanner())
            status = engine.run()
            reflection = {k: "" for k in PLAN_FIELDS}
            reflection.update(request_id=echo.id, kind="reflection", session="anonymous", location="query", field="q",
                              hypothesis="[DEMO] 무해한 표식 반사", expected_evidence="브라우저 실행은 별도 확인")
            engine.execute(reflection)
            report = render(engine, output / "bounty_demo.html")
            findings = [r for r in store.all("results") if r.get("kind") != "observation"]
            print(json.dumps({"mode": "DEMO; no real GPT calls", "status": status,
                              "states": [r["state"] for r in findings], "http_requests": len(server.hits), "report": str(report)}, ensure_ascii=False))
    finally:
        store.db.close()


if __name__ == "__main__":
    main()
