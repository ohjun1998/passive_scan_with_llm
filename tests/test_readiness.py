import json
import io
import os
import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from bounty_assist.__main__ import main
from bounty_assist.console import configure_console
from bounty_assist.data import Request
from bounty_assist.engine import Engine
from bounty_assist.planner import CodexPlanner
from bounty_assist.runtime import Config
from bounty_assist.store import Store
from lab import config_for, lab


class ReadinessTests(unittest.TestCase):
    def test_korean_console_output_is_safe_under_windows_legacy_encoding(self):
        raw = io.BytesIO()
        stream = io.TextIOWrapper(raw, encoding='cp1252')
        with patch('sys.stdout', stream):
            configure_console()
            print('한국어 진단 결과', flush=True)
        self.assertEqual(raw.getvalue().decode('utf-8').strip(), '한국어 진단 결과')
        stream.detach()

    def test_windows_npm_shim_uses_node_without_shell_and_unicode(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            entry = root / 'node_modules/@openai/codex/bin/codex.js'
            entry.parent.mkdir(parents=True)
            entry.write_text('// official npm entry fixture')
            shim = str(root / 'codex.cmd')
            def run(command, **kwargs):
                self.assertEqual(command[:2], ['node.exe', str(entry)])
                self.assertFalse(kwargs.get('shell', False))
                self.assertEqual(kwargs['encoding'], 'utf-8')
                if command[2:] == ['login', 'status']:
                    return subprocess.CompletedProcess(command, 0, 'Logged in using ChatGPT', '')
                Path(command[command.index('-o') + 1]).write_text(json.dumps({'notes': '한국어 계획', 'plans': []}), encoding='utf-8')
                return subprocess.CompletedProcess(command, 0, '{"type":"turn.completed","usage":{"input_tokens":10,"output_tokens":5}}', '')
            with patch('shutil.which', side_effect=lambda name: 'node.exe' if name == 'node' else shim), patch('subprocess.run', side_effect=run):
                planner = CodexPlanner(Config({'origins': ['https://x.test']}))
                answer, usage = planner.plan({'previous_results': []})
            self.assertEqual(answer['notes'], '한국어 계획')
            self.assertEqual(usage['output_tokens'], 5)

    def test_adaptive_effort_only_for_meaningful_signals(self):
        with patch('shutil.which', return_value='/mock/codex'), patch('subprocess.run', return_value=subprocess.CompletedProcess([], 0, 'Logged in using ChatGPT', '')):
            config = Config({'origins': ['https://x.test'], 'codex': {'adaptive_reasoning': True}})
            planner = CodexPlanner(config)
            self.assertEqual(planner.effort({'previous_results': [{'state': 'reflection_signal'}]}), 'low')
            self.assertEqual(planner.effort({'previous_results': [{'state': 'auth_candidate'}]}), 'medium')
            config.codex['adaptive_reasoning'] = False
            self.assertEqual(planner.effort({'previous_results': [{'state': 'auth_candidate'}]}), 'low')

    def test_soft_budget_stops_next_group_and_does_not_double_count(self):
        class MeteredPlanner:
            is_live = True
            def plan(self, context):
                return {'notes': 'done', 'plans': []}, {'input_tokens': 7, 'output_tokens': 5, 'cached_input_tokens': 3, 'reasoning_output_tokens': 2}
        with tempfile.TemporaryDirectory() as folder, lab() as (base, server):
            store = Store(folder)
            try:
                store.add(Request(base + '/echo?q=hello'))
                store.add(Request(base + '/condition?q=true'))
                config = config_for(base)
                config['sessions'] = {'anonymous': {'headers_env': {}, 'origins': []}}
                config['max_model_tokens'] = 10
                engine = Engine(store, Config(config), MeteredPlanner())
                self.assertTrue(engine.run()['stopped'])
                self.assertEqual(store.count('model_tokens'), 12)
                self.assertEqual(store.count('ai_calls'), 1)
                # Replaying a cached round must not meter its usage a second time.
                engine.run()
                self.assertEqual(store.count('model_tokens'), 12)
                config['max_model_tokens'] = 30
                resumed = Engine(store, Config(config), MeteredPlanner()).run()
                self.assertFalse(resumed['stopped'])
                self.assertEqual(store.count('ai_calls'), 2)
                self.assertEqual(store.count('model_tokens'), 24)
                self.assertEqual(len(server.hits), 2)
            finally:
                store.db.close()

    def test_unknown_usage_requires_explicit_acknowledgement(self):
        with tempfile.TemporaryDirectory() as folder:
            store = Store(folder)
            store.record_model_usage({}, live=True)
            store.increment('model_tokens', 20)
            store.db.close()
            self.assertEqual(main(['--workspace', folder, 'usage', '--acknowledge-unknown']), 0)
            store = Store(folder)
            try:
                self.assertEqual(store.count('model_usage_acknowledged_calls'), 1)
                self.assertEqual(store.count('model_tokens'), 20)
            finally:
                store.db.close()

    def test_context_is_bounded_even_for_one_large_capture(self):
        with tempfile.TemporaryDirectory() as folder:
            store = Store(folder)
            try:
                req = Request('https://x.test/api?q=1')
                store.add(req, {'status': 200, 'body': 'x' * 50000, 'headers': {}})
                engine = Engine(store, Config({'origins': ['https://x.test'], 'max_context_chars': 4000}))
                context = engine.context([req])
                self.assertLessEqual(len(json.dumps(context, ensure_ascii=False)), 4000)
            finally:
                store.db.close()

    def test_group_limit_resumes_remaining_groups(self):
        with tempfile.TemporaryDirectory() as folder, lab() as (base, server):
            store = Store(folder)
            try:
                store.add(Request(base + '/echo?q=hello'))
                store.add(Request(base + '/condition?q=true'))
                config = Config({'origins': [base], 'allow_private': True, 'max_groups': 1, 'requests_per_second': 10000})
                engine = Engine(store, config)
                first = engine.run()
                self.assertTrue(first['stopped'])
                self.assertEqual(first['groups_remaining'], 1)
                second = engine.run()
                self.assertFalse(second['stopped'])
                self.assertEqual(second['groups_remaining'], 0)
                self.assertEqual(len(server.hits), 2)
            finally:
                store.db.close()

    def test_doctor_live_checks_model_without_target_http(self):
        with tempfile.TemporaryDirectory() as folder:
            with patch('bounty_assist.__main__.CodexPlanner') as bridge, patch('bounty_assist.runtime.Transport.send', side_effect=AssertionError('No target traffic allowed')):
                bridge.return_value.plan.return_value = ({'notes': 'MODEL_CALL_OK', 'plans': []}, {'input_tokens': 10, 'output_tokens': 5})
                self.assertEqual(main(['--workspace', folder, 'doctor', '--live']), 0)
            store = Store(folder)
            try:
                self.assertEqual(store.count('model_tokens'), 15)
                self.assertEqual(store.count('ai_calls'), 1)
                self.assertEqual(store.count('http_requests'), 0)
            finally:
                store.db.close()

    def test_different_planners_do_not_reuse_simulated_answers(self):
        class Simulated:
            def plan(self, context):
                return {'notes': 'simulation', 'plans': []}, {}
        class ActualBridgeFixture:
            def plan(self, context):
                return {'notes': 'different bridge', 'plans': []}, {'input_tokens': 10, 'output_tokens': 5}
        with tempfile.TemporaryDirectory() as folder, lab() as (base, server):
            store = Store(folder)
            try:
                store.add(Request(base + '/echo?q=hello'))
                config = Config({'origins': [base], 'allow_private': True, 'requests_per_second': 10000})
                Engine(store, config, Simulated()).run()
                Engine(store, config, ActualBridgeFixture()).run()
                self.assertEqual(store.count('ai_calls'), 2)
                self.assertEqual(store.count('model_tokens'), 15)
                self.assertEqual(len(server.hits), 1)
            finally:
                store.db.close()

    def test_interrupted_live_call_is_recovered_as_unknown_usage_once(self):
        with tempfile.TemporaryDirectory() as folder:
            store = Store(folder)
            store.call('abandoned', 'started', {'status': 'started', 'is_live': True})
            store.db.close()
            for _ in range(2):
                store = Store(folder)
                self.assertEqual(store.count('model_usage_unknown_calls'), 1)
                self.assertEqual(store.get('calls', 'abandoned')['status'], 'interrupted')
                store.db.close()


if __name__ == '__main__':
    unittest.main()
