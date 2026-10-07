import json
import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

import global_mixer


class ReconIntegrationTests(unittest.TestCase):
    def test_raw_katana_and_all_object_variants_survive_in_seed(self):
        with tempfile.TemporaryDirectory() as directory:
            previous = os.getcwd()
            os.chdir(directory)
            try:
                Path("results").mkdir()
                Path("previous_report").mkdir()
                Path("targets.txt").write_text("example.test\n")
                routes = ["https://example.test/api/profile", "https://example.test/api/orders", "https://example.test/api/permissions"]
                objects = [f"https://example.test/api/orders/{i}" for i in range(1, 9)]
                Path("results/example.test_katana_raw_00.txt").write_text("\n".join(routes + objects))
                Path("previous_report/master_url_db.txt").write_text("https://outside.test/private\nhttps://example.test/api/history\n")
                global_mixer.run_mixer()
                seed = [json.loads(line)["url"] for line in Path("chunks/bounty_seed.jsonl").read_text().splitlines()]
                self.assertTrue(set(routes + objects).issubset(seed))
                self.assertNotIn("https://outside.test/private", seed)
                probes = "\n".join(p.read_text() for p in Path("chunks").glob("chunk_*.txt"))
                for route in routes:
                    self.assertIn(route, probes)
                self.assertEqual(sum(url in probes.splitlines() for url in objects), 5)
            finally:
                os.chdir(previous)


if __name__ == "__main__":
    unittest.main()
