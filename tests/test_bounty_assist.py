import json
import os
import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from bounty_assist.data import Redactor, Request, import_records, path_template
from bounty_assist.engine import Engine, matches
from bounty_assist.planner import CodexPlanner, DemoPlanner, PLAN_FIELDS, validate_plan
from bounty_assist.report import render
from bounty_assist.runtime import Config, Transport, mutate
from bounty_assist.store import Store
from lab import config_for, lab


def plan(req, kind="auth", session="user_b", location="none", field="", value="", control=""):
    record = {name: "" for name in PLAN_FIELDS}
    record.update(request_id=req.id, kind=kind, session=session, location=location, field=field, value=value, control=control,
                  hypothesis="테스트", expected_evidence="대조 증거")
    return record


class DataTests(unittest.TestCase):
    def test_group_preserves_function_and_body_structure(self):
        self.assertEqual(Request("https://x.test/orders/1").group, Request("https://x.test/orders/2").group)
        self.assertNotEqual(Request("https://x.test/api/profile").group, Request("https://x.test/api/orders").group)
        self.assertEqual(path_template("/api/authorization/1"), "/api/authorization/{id}")
        a = Request("https://x.test/orders/1", "POST", {"Content-Type": "application/json"}, '{"item":{"id":1}}')
        b = Request("https://x.test/orders/2", "POST", {"Content-Type": "application/json"}, '{"item":{"name":"x"}}')
        self.assertNotEqual(a.group, b.group)
        self.assertNotEqual(Request(a.url, owner="a").id, Request(a.url, owner="b").id)
        self.assertEqual(Request(a.url, source="a.txt").id, Request(a.url, source="b.jsonl").id)

    def test_har_credentials_and_multipart(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "capture.har"
            path.write_text(json.dumps({"log": {"entries": [{"request": {"url": "https://x.test/api/order/1", "method": "POST",
                "headers": [{"name": "Cookie", "value": "secret-cookie"}], "postData": {"mimeType": "application/json", "text": '{"id":1}'}},
                "response": {"status": 200, "content": {"text": '{"owner":"a"}'}}}]}}))
            records = list(import_records(path, "user_a", "a"))
            self.assertEqual(records[0][0].headers, {"content-type": "application/json"})
            self.assertEqual(records[0][0].session, "user_a")
            self.assertEqual(records[0][1]["status"], 200)
            har = json.loads(path.read_text())
            har["log"]["entries"][0]["request"]["postData"]["mimeType"] = "multipart/form-data"
            path.write_text(json.dumps(har))
            self.assertFalse(list(import_records(path))[0][0].replayable)
            har["log"]["entries"][0]["request"]["postData"] = {"mimeType": "application/x-www-form-urlencoded", "params": [{"name": "q", "value": "hello world"}]}
            path.write_text(json.dumps(har))
            form = list(import_records(path))[0][0]
            self.assertTrue(form.replayable)
            self.assertEqual(form.body, "q=hello+world")

    def test_redaction_keeps_stable_owner_aliases(self):
        r = Redactor(b"salt", ["sid=private-cookie"])
        output = r.body('{"token":"private-token","owner":"someone@example.com"}')
        self.assertNotIn("private-token", output)
        self.assertNotIn("someone@example.com", output)
        self.assertEqual(r.text("someone@example.com"), r.obj("someone@example.com"))
        self.assertNotIn("private-cookie", r.text("sid=private-cookie"))
        self.assertNotIn("xml-secret", r.body("<AccessToken>xml-secret</AccessToken>"))
        self.assertNotIn("private-token", r.url("https://x.test/?access_token=private-token"))

    def test_mutation_preserves_scope_and_existing_fields(self):
        req = Request("https://x.test/api/orders/1?q=one&q=two&keep=ok")
        changed = mutate(req, "query", "q", "hello world")
        self.assertIn("keep=ok", changed.url)
        with self.assertRaises(ValueError):
            mutate(req, "query", "missing", "x")
        for value in ("../admin", "https://evil.test", "%2fadmin"):
            with self.assertRaises(ValueError):
                mutate(req, "path", "3", value)
        body = Request("https://x.test/api", "POST", {"content-type": "application/json"}, '{"items":[{"name":"old"}]}')
        self.assertEqual(json.loads(mutate(body, "json", "/items/0/name", "new").body)["items"][0]["name"], "new")

    def test_url_rejects_credentials_and_controls(self):
        for url in ("https://u:p@x.test/", "file:///etc/passwd", "https://x.test/\nheader"):
            with self.assertRaises(ValueError):
                Request(url)

    def test_evidence_strict_types_and_truncated(self):
        self.assertFalse(matches({"status": 200, "body": '{"id":true}'}, "/id", 1))
        self.assertFalse(matches({"status": 200, "body": '{"id":1}', "truncated": True}, "/id", 1))


class EngineTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.store = Store(Path(self.temp.name) / "state")
        self.environment = patch.dict(os.environ, {"LAB_COOKIE_A": "sid=lab-user-a", "LAB_COOKIE_B": "sid=lab-user-b"})
        self.environment.start()

    def tearDown(self):
        self.environment.stop()
        self.store.db.close()
        self.temp.cleanup()

    def engine(self, base, path="/api/orders/1", config_change=None, planner=None):
        req = Request(base + path, session="user_a", owner="user-a")
        control = Request(base + "/api/orders/999")
        self.store.add(req)
        self.store.add(control)
        data = config_for(base)
        data["policies"] = [{"request_id": req.id, "owner_session": "user_a", "denied_sessions": ["user_b"],
                             "json_pointer": "/private", "equals": "lab-private-order", "control_request_id": control.id}]
        if config_change:
            config_change(data)
        return Engine(self.store, Config(data), planner), req

    def test_auth_vulnerability_and_fixed_endpoint(self):
        with lab() as (base, server):
            engine, req = self.engine(base)
            result = engine.execute(plan(req))
            self.assertEqual(result["state"], "auth_candidate")
            self.assertTrue(result["evidence"]["negative_control_valid"])
            self.assertEqual(len(result["evidence"]["other"]), 2)
            fixed, request2 = self.engine(base, "/api/orders/2")
            self.assertEqual(fixed.execute(plan(request2))["state"], "not_reproduced")

    def test_200_login_page_not_auth_finding(self):
        with lab() as (base, server):
            engine, req = self.engine(base, "/login-fallback")
            self.assertEqual(engine.execute(plan(req))["state"], "inconclusive")

    def test_missing_identity_check_and_wrong_session(self):
        with lab() as (base, server):
            engine, req = self.engine(base, config_change=lambda d: d["sessions"]["user_b"].pop("health"))
            self.assertEqual(engine.execute(plan(req))["state"], "inconclusive")
            self.assertFalse(any(p == "/api/orders/1" for p, _ in server.hits))
            with patch.dict(os.environ, {"LAB_COOKIE_B": "sid=lab-user-a"}):
                engine2, req2 = self.engine(base)
                self.assertEqual(engine2.execute(plan(req2))["state"], "inconclusive")

    def test_negative_control_cannot_expose_same_private_data(self):
        with lab() as (base, server):
            control = Request(base + "/api/orders/2")
            self.store.add(control)
            engine, req = self.engine(base, config_change=lambda d: d["policies"][0].update(control_request_id=control.id))
            # Give the control a 200 matching object; auth evidence must be rejected.
            original = engine.transport.send
            def send(request, session):
                if request.id == control.id:
                    return {"status": 200, "body": '{"private":"lab-private-order"}', "headers": {}}
                return original(request, session)
            with patch.object(engine.transport, "send", side_effect=send):
                self.assertEqual(engine.execute(plan(req))["state"], "inconclusive")

    def test_reflection_and_echo_difference_not_sqli(self):
        with lab() as (base, server):
            req = Request(base + "/echo?q=original")
            self.store.add(req)
            engine = Engine(self.store, Config(config_for(base)))
            reflected = engine.execute(plan(req, "reflection", "anonymous", "query", "q"))
            self.assertEqual(reflected["state"], "reflection_signal")
            comparison = engine.execute(plan(req, "compare", "anonymous", "query", "q", "true", "false"))
            self.assertEqual(comparison["state"], "not_reproduced")
            cond = Request(base + "/condition?q=original")
            self.store.add(cond)
            engine = Engine(self.store, Config(config_for(base)))
            signal = engine.execute(plan(cond, "compare", "anonymous", "query", "q", "true", "false"))
            self.assertEqual(signal["state"], "differential_signal")

    def test_scope_credentials_methods_and_private_dns(self):
        with lab() as (base, server):
            data = config_for(base)
            config = Config(data)
            transport = Transport(config, self.store)
            for request, session in ((Request("https://outside.test/"), "user_a"),
                                     (Request(base + "/api", "DELETE"), "user_a"),
                                     (Request(base + "/api?action=delete"), "user_a"),
                                     (Request(base + "/api?token=secret"), "anonymous")):
                with self.assertRaises(ValueError):
                    transport.send(request, session)
            data["allow_private"] = False
            with self.assertRaises(ValueError):
                Transport(Config(data), self.store).send(Request(base + "/api/me"), "anonymous")
            self.assertEqual(server.hits, [])

    def test_redirect_does_not_forward_credentials(self):
        with lab() as (base, server):
            response = Transport(Config(config_for(base)), self.store).send(Request(base + "/redirect"), "user_a")
            self.assertEqual(response["status"], 302)
            self.assertFalse(response["redirect_followed"])
            self.assertEqual(server.hits, [("/redirect", "user-a")])

    def test_missing_env_does_not_silently_use_anonymous(self):
        with patch.dict(os.environ, {}, clear=True):
            with self.assertRaises(ValueError):
                Config(config_for("https://x.test"))

    def test_persistent_budget_and_resume_without_duplicate_calls(self):
        with lab() as (base, server):
            engine, req = self.engine(base, planner=DemoPlanner())
            self.assertFalse(engine.run()["stopped"])
            requests_before, calls_before = self.store.count("http_requests"), self.store.count("ai_calls")
            self.assertFalse(engine.run()["stopped"])
            self.assertEqual(self.store.count("http_requests"), requests_before)
            self.assertEqual(self.store.count("ai_calls"), calls_before)
            data = config_for(base)
            data["max_requests"] = requests_before
            extra = Request(base + "/login-fallback")
            self.store.add(extra)
            stopped = Engine(self.store, Config(data)).run()
            self.assertTrue(stopped["stopped"])
            self.assertEqual(self.store.count("http_requests"), requests_before)

    def test_http_backoff_stops(self):
        with lab() as (base, server):
            req = Request(base + "/throttle")
            self.store.add(req)
            stopped = Engine(self.store, Config(config_for(base))).run()
            self.assertTrue(stopped["stopped"])
            self.assertEqual(len(server.hits), 1)

    def test_html_escapes_attacker_content_and_masks_cookie(self):
        with lab() as (base, server):
            engine, req = self.engine(base)
            malicious = plan(req, "manual")
            malicious["hypothesis"] = '<script>alert("x")</script>'
            malicious["prerequisites"] = "sid=lab-user-a"
            engine.execute(malicious)
            path = Path(self.temp.name) / "report.html"
            render(engine, path)
            text = path.read_text()
            self.assertNotIn(malicious["hypothesis"], text)
            self.assertIn("&lt;script&gt;", text)
            self.assertNotIn("sid=lab-user-a", text)
            if os.name != "nt":
                self.assertEqual(path.stat().st_mode & 0o777, 0o600)

    def test_unknown_request_plan_is_rejected(self):
        with lab() as (base, server):
            engine, req = self.engine(base)
            invalid = plan(req)
            invalid["request_id"] = "fake"
            with self.assertRaises(ValueError):
                validate_plan(invalid, engine.requests, engine.config)

    def test_invalid_ai_schema_is_recorded_without_execution(self):
        class BrokenPlanner:
            def plan(self, context):
                return {"notes": "bad output", "plans": [{"kind": "auth"}]}, {}
        with lab() as (base, server):
            req = Request(base + "/api/me")
            self.store.add(req)
            engine = Engine(self.store, Config(config_for(base)), BrokenPlanner())
            self.assertFalse(engine.run()["stopped"])
            self.assertTrue(any(r.get("state") == "rejected" for r in self.store.all("results")))
            self.assertEqual(len(server.hits), 1)


class CodexBridgeTests(unittest.TestCase):
    def test_official_cli_schema_auth_usage_and_secret_environment(self):
        config = Config({"origins": ["https://x.test"]})
        result = {"notes": "검증 계획", "plans": []}
        commands = []
        def run(command, **kwargs):
            commands.append(command)
            self.assertNotIn("OPENAI_API_KEY", kwargs["env"])
            self.assertNotIn("CODEX_API_KEY", kwargs["env"])
            if command[1:3] == ["login", "status"]:
                return subprocess.CompletedProcess(command, 0, "", "Logged in using ChatGPT")
            self.assertIn("features.shell_tool=false", command)
            self.assertIn("--output-schema", command)
            self.assertIn("--ignore-user-config", command)
            Path(command[command.index("-o") + 1]).write_text(json.dumps(result))
            return subprocess.CompletedProcess(command, 0, '{"type":"turn.completed","usage":{"input_tokens":123}}\n', "")
        with patch("shutil.which", return_value="/mock/codex"), patch("subprocess.run", side_effect=run), patch.dict(os.environ, {"OPENAI_API_KEY": "should-not-bill", "CODEX_API_KEY": "should-not-bill"}):
            planner = CodexPlanner(config)
            answer, usage = planner.plan({"requests": [], "previous_results": [], "policies": []})
        self.assertEqual(answer, result)
        self.assertEqual(usage["input_tokens"], 123)
        self.assertEqual(len(commands), 2)

    def test_api_auth_is_rejected(self):
        with patch("shutil.which", return_value="/mock/codex"), patch("subprocess.run", return_value=subprocess.CompletedProcess([], 0, "Logged in using an API key", "")):
            with self.assertRaises(RuntimeError):
                CodexPlanner(Config({"origins": ["https://x.test"]}))


if __name__ == "__main__":
    unittest.main()
