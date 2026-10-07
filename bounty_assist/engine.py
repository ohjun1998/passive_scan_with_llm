import json
import time
from collections import defaultdict
from dataclasses import asdict

from .data import Redactor, Request, digest, origin
from .planner import validate_plan
from .runtime import BudgetExceeded, Transport, mutate, pointer


def usable(response):
    return (200 <= response.get("status", 0) < 300 and not response.get("truncated")
            and not response.get("unreadable") and not response.get("error"))


def matches(response, field, expected):
    if not usable(response):
        return False
    try:
        actual = pointer(json.loads(response["body"]), field)
        return type(actual) is type(expected) and actual == expected
    except (ValueError, KeyError, IndexError, TypeError):
        return False


def comparable(response, values=()):
    """Exclude mere payload echoes and known clock noise from differential signals."""
    body = response.get("body", "")
    for value in sorted({v for v in values if v}, key=len, reverse=True):
        body = body.replace(value, "[input]")
    try:
        value = json.loads(body)
        def clean(item):
            if isinstance(item, dict):
                return {k: clean(v) for k, v in item.items() if k.lower() not in ("timestamp", "request_id", "trace_id")}
            if isinstance(item, list):
                return [clean(v) for v in item]
            return item
        body = json.dumps(clean(value), sort_keys=True)
    except ValueError:
        pass
    return digest([response.get("status"), body])


class Engine:
    def __init__(self, store, config, planner=None):
        self.store, self.config, self.planner = store, config, planner
        self.requests = {r.id: r for r in store.requests()}
        self.transport = Transport(config, store)
        self.redactor = Redactor(store.salt, config.secret_values())
        self.context_key = digest([config.data, self.redactor.obj(config.headers)])
        self.policies = self.resolve_policies()

    def find_request(self, url, session=None):
        matches_ = [r for r in self.requests.values() if r.url == url and (session is None or r.session == session)]
        if len(matches_) != 1:
            raise ValueError("Policy URL must resolve to exactly one imported request; use request_id for ambiguity")
        return matches_[0].id

    def resolve_policies(self):
        policies = []
        for original in self.config.data["policies"]:
            policy = dict(original)
            policy["request_id"] = policy.get("request_id") or self.find_request(policy["request_url"], policy["owner_session"])
            policy["control_request_id"] = policy.get("control_request_id") or self.find_request(policy["control_url"])
            if policy["request_id"] not in self.requests or policy["control_request_id"] not in self.requests:
                raise ValueError("Policy refers to unknown request")
            owner = policy["owner_session"]
            if owner not in self.config.headers or owner == "anonymous":
                raise ValueError("Policy must name a configured authenticated owner")
            if not isinstance(policy["denied_sessions"], list) or not policy["denied_sessions"]:
                raise ValueError("Policy must list denied_sessions")
            if any(s not in self.config.headers or s == owner for s in policy["denied_sessions"]):
                raise ValueError("Invalid denied_sessions")
            if not isinstance(policy["json_pointer"], str) or not policy["json_pointer"].startswith("/"):
                raise ValueError("Policy requires a JSON Pointer to private object evidence")
            if type(policy["equals"]) not in (str, int, float, bool) or policy["equals"] == "":
                raise ValueError("Policy evidence must be a nonempty scalar")
            target = self.requests[policy["request_id"]]
            control = self.requests[policy["control_request_id"]]
            if origin(target.url) != origin(control.url) or target.id == control.id:
                raise ValueError("Control must be a different imported request on the same origin")
            policies.append(policy)
        return policies

    def observe(self, req, session, tag):
        key = digest([self.context_key, asdict(req), session, tag])
        cached = self.store.get("results", key)
        ttl = self.config.data.get("evidence_ttl_seconds", 900)
        if cached and time.time() - cached.get("recorded_at", 0) < ttl:
            return cached["response"]
        try:
            response = self.transport.send(req, session)
        except BudgetExceeded:
            raise
        except Exception as exc:
            # Failed network/validation attempts remain inconclusive.
            response = {"status": 0, "body": "", "headers": {}, "error": self.redactor.text(str(exc))[:300]}
        result = {"kind": "observation", "request_id": req.id, "session": session, "tag": tag,
                  "request": asdict(req), "response": response, "recorded_at": time.time()}
        self.store.put("results", key, result)
        if response.get("status") in (429, 503):
            raise BudgetExceeded("Target requested backoff (HTTP 429/503); resume later")
        return response

    def session_health(self, session, target):
        if session == "anonymous":
            return True  # No captured cookies or authorization headers are used.
        health = self.config.data["sessions"][session].get("health")
        if not health:
            return False
        req = Request(health["url"], session=session, source="configured-health")
        if origin(req.url) != origin(target.url):
            return False
        response = self.observe(req, session, "session-health")
        return matches(response, health["json_pointer"], health["equals"])

    def auth(self, plan, req):
        session = plan["session"]
        policy = next((p for p in self.policies if p["request_id"] == req.id and session in p["denied_sessions"]), None)
        if not policy:
            # Collect a pair, but cannot assert an authorization violation.
            owner = self.observe(req, req.session, "baseline")
            other = self.observe(req, session, "auth-unconfigured")
            return "inconclusive", "권한 정답표·객체 증거·대조 요청이 없어 판정 불가", {"owner": owner, "other": other}
        if not self.session_health(policy["owner_session"], req) or not self.session_health(session, req):
            return "inconclusive", "계정 신원을 검증할 수 없음: health URL/필드 또는 세션 상태 확인 필요", {}
        owner_responses = [self.observe(req, policy["owner_session"], f"auth-owner-{i}") for i in range(2)]
        other_responses = [self.observe(req, session, f"auth-other-{i}") for i in range(2)]
        control_req = self.requests[policy["control_request_id"]]
        controls = [self.observe(control_req, session, f"auth-control-{i}") for i in range(2)]
        field, expected = policy["json_pointer"], policy["equals"]
        owners_match = all(matches(r, field, expected) for r in owner_responses)
        others_match = all(matches(r, field, expected) for r in other_responses)
        controls_valid = all((400 <= r.get("status", 0) < 500 or usable(r))
                             and not r.get("error") and not r.get("truncated") and not r.get("unreadable")
                             and not matches(r, field, expected) for r in controls)
        evidence = {"owner": owner_responses, "other": other_responses, "control": controls,
                    "owner_evidence": owners_match, "other_evidence": others_match, "negative_control_valid": controls_valid}
        if owners_match and others_match and controls_valid:
            return "auth_candidate", "차단 대상 계정에서 비공개 객체 증거가 2회 재현됨; 정책과 영향 최종 검토 필요", evidence
        if owners_match and all(r.get("status") in (401, 403, 404) for r in other_responses):
            return "not_reproduced", "이번 요청에서는 권한 우회가 재현되지 않음", evidence
        return "inconclusive", "소유자·대조 요청·반복 결과가 충분하지 않아 판정 불가", evidence

    def execute(self, plan):
        validate_plan(plan, self.requests, self.config)
        req = self.requests[plan["request_id"]]
        # Deduplicate mechanics, independent of differently worded AI rationales.
        mechanics = {k: plan[k] for k in ("request_id", "kind", "session", "location", "field", "value", "control")}
        key = digest([self.context_key, mechanics])
        cached = self.store.get("results", key)
        if cached and time.time() - cached.get("recorded_at", 0) < self.config.data.get("evidence_ttl_seconds", 900):
            return cached
        evidence = {}
        if plan["kind"] == "manual":
            state, reason = "manual_required", plan["prerequisites"] or "전용 실행기 또는 추가 계정·업무 흐름 필요"
        elif plan["kind"] == "auth":
            state, reason, evidence = self.auth(plan, req)
        else:
            baseline = self.observe(req, plan["session"], "baseline")
            if plan["kind"] == "reflection":
                marker = "bounty_marker_" + key[:16]
                changed = mutate(req, plan["location"], plan["field"], marker)
                response = self.observe(changed, plan["session"], "reflection")
                reflected = usable(response) and marker in response["body"] and marker not in baseline.get("body", "")
                state = "reflection_signal" if reflected else "not_reproduced" if usable(baseline) and usable(response) else "inconclusive"
                reason = "무해한 표식 반사 확인; XSS 실행 여부는 브라우저 검증 필요" if reflected else "반사 증거 없음 또는 요청 실패"
                evidence = {"baseline": baseline, "probe": response, "marker": marker}
            else:
                changed = mutate(req, plan["location"], plan["field"], plan["value"])
                control = mutate(req, plan["location"], plan["field"], plan["control"])
                # Interleave test/control to reduce drift and load-related false signals.
                tests, controls = [], []
                for i in range(2):
                    tests.append(self.observe(changed, plan["session"], f"compare-test-{i}"))
                    controls.append(self.observe(control, plan["session"], f"compare-control-{i}"))
                values = (plan["value"], plan["control"])
                stable = (all(usable(r) for r in tests + controls) and
                          comparable(tests[0], values) == comparable(tests[1], values) and
                          comparable(controls[0], values) == comparable(controls[1], values))
                different = stable and comparable(tests[0], values) != comparable(controls[0], values)
                state = "differential_signal" if different else "not_reproduced" if stable else "inconclusive"
                reason = "반복된 조건별 응답 차이; 취약점 유형과 영향은 추가 검증 필요" if different else "일관된 차이 없음 또는 결과 불안정"
                evidence = {"baseline": baseline, "test": tests, "control": controls}
        result = {**plan, "state": state, "reason": reason, "evidence": evidence, "recorded_at": time.time()}
        self.store.put("results", key, result)
        return result

    def safe_response(self, response):
        result = self.redactor.obj(response)
        if "body" in response:
            result["body"] = self.redactor.body(response["body"])[:4000]
        if "headers" in response:
            result["headers"] = self.redactor.obj({k.lower(): v for k, v in response["headers"].items()})
        return result

    def safe_result(self, result):
        if isinstance(result, list):
            return [self.safe_result(x) for x in result]
        if not isinstance(result, dict):
            return self.redactor.obj(result)
        if "body" in result and "status" in result:
            return self.safe_response(result)
        output = {k: self.safe_result(v) for k, v in result.items()}
        if "url" in result:
            output["url"] = self.redactor.url(result["url"])
        if "body" in result:
            output["body"] = self.redactor.body(result["body"])[:4000]
        if "headers" in result:
            output["headers"] = self.redactor.obj({k.lower(): v for k, v in result["headers"].items()})
        return output

    def safe_plan(self, plan):
        output = self.redactor.obj(plan)
        # These are session REFERENCES, never captured credential material.
        output["session"] = plan["session"]
        return output

    def context(self, group):
        # Preserve representatives across accounts and owners before filling the sample cap.
        reps, seen = [], set()
        cap = self.config.data["samples_per_group"]
        for req in sorted(group, key=lambda r: (r.session, r.owner, r.id)):
            identity = (req.session, req.owner)
            if identity not in seen:
                reps.append(req)
                seen.add(identity)
        for req in group:
            if req not in reps and len(reps) < cap:
                reps.append(req)
        reps = reps[:cap]
        requests = []
        for req in reps:
            item = self.redactor.request(req)
            item["captured_responses"] = [self.safe_response(r) for r in self.store.captures(req.id)]
            requests.append(item)
        ids = {r.id for r in reps}
        previous = [self.safe_result(r) for r in self.store.all("results") if r.get("request_id") in ids][-12:]
        context = {"requests": requests, "group_total_requests": len(group), "sampled_requests": len(reps),
                   "sessions": [{"name": s, "has_identity_check": bool(c.get("health"))}
                                for s, c in self.config.data["sessions"].items()],
                   "policies": [{"request_id": p["request_id"], "owner_session": p["owner_session"],
                                 "denied_sessions": p["denied_sessions"], "json_pointer": p["json_pointer"],
                                 "equals": self.redactor.obj(p["equals"]), "control_request_id": p["control_request_id"]}
                                for p in self.policies if p["request_id"] in ids],
                   "previous_results": previous}
        # Bound input while preserving syntactically complete JSON.
        while len(json.dumps(context, ensure_ascii=False)) > 40000:
            if context["previous_results"]:
                context["previous_results"].pop(0)
            elif len(context["requests"]) > 1:
                context["requests"].pop()
                context["sampled_requests"] = len(context["requests"])
            else:
                break
        return context

    def run(self):
        groups = defaultdict(list)
        for req in self.requests.values():
            groups[req.group].append(req)
        ordered = sorted(groups.values(), key=lambda g: (-max(r.priority for r in g), g[0].group))
        try:
            for group in ordered[:self.config.data["max_groups"]]:
                print(f"[+] 기능 {group[0].group}: 요청 {len(group)}개", flush=True)
                for req in group[:self.config.data["samples_per_group"]]:
                    self.observe(req, req.session, "baseline")
                # Policy-defined auth tests work even without an LLM.
                for policy in self.policies:
                    if policy["request_id"] not in {r.id for r in group}:
                        continue
                    for session in policy["denied_sessions"]:
                        plan = {k: "" for k in ("request_id", "kind", "session", "location", "field", "value", "control", "hypothesis", "expected_evidence", "prerequisites")}
                        plan.update(request_id=policy["request_id"], kind="auth", session=session, location="none",
                                    hypothesis="설정된 비공개 객체의 계정별 접근 검증", expected_evidence="소유자·반복 요청·음성 대조 확인")
                        self.execute(plan)
                if not self.planner:
                    continue
                for round_number in range(self.config.data["rounds"]):
                    context = self.context(group)
                    key = digest([self.context_key, group[0].group, round_number,
                                  sorted(r.id for r in group),
                                  [self.store.captures(r.id) for r in group]])
                    cached = self.store.get("calls", key)
                    if (cached and cached.get("status") == "completed" and
                            time.time() - cached.get("recorded_at", 0) < self.config.data["evidence_ttl_seconds"]):
                        answer = cached["answer"]
                    else:
                        if not self.store.reserve("ai_calls", self.config.data["max_ai_calls"]):
                            raise BudgetExceeded("AI call budget exhausted")
                        self.store.call(key, "started", {"status": "started", "group": group[0].group})
                        try:
                            answer, usage = self.planner.plan(context)
                        except Exception as exc:
                            self.store.call(key, "failed", {"status": "failed", "group": group[0].group,
                                                           "error": self.redactor.text(str(exc))[:500]})
                            raise
                        valid_plans = []
                        for candidate in answer["plans"][:self.config.data["max_plans_per_group"]]:
                            try:
                                validate_plan(candidate, self.requests, self.config)
                            except ValueError as exc:
                                self.store.put("results", digest([key, candidate, "schema-rejected"]),
                                               {"kind": "rejected_plan", "state": "rejected",
                                                "plan": self.redactor.obj(candidate), "reason": str(exc)})
                                continue
                            valid_plans.append(self.safe_plan(candidate))
                        answer = {"notes": self.redactor.text(answer["notes"])[:4000], "plans": valid_plans}
                        self.store.call(key, "completed", {"status": "completed", "group": group[0].group,
                                                          "answer": answer, "usage": usage, "recorded_at": time.time()})
                    if not answer["plans"]:
                        break
                    for plan in answer["plans"][:self.config.data["max_plans_per_group"]]:
                        self.store.put("plans", digest([key, plan]), self.safe_plan(plan))
                        try:
                            if plan["request_id"] not in {r["id"] for r in context["requests"]}:
                                raise ValueError("Plan references a request outside its supplied group")
                            self.execute(plan)
                        except ValueError as exc:
                            self.store.put("results", digest([key, plan, "rejected"]),
                                           {"kind": "rejected_plan", "state": "rejected", "plan": self.redactor.obj(plan), "reason": str(exc)})
        except BudgetExceeded as exc:
            return {"stopped": True, "reason": str(exc)}
        return {"stopped": False, "reason": "처리 완료; 미확인 항목은 안전 판정이 아님"}
