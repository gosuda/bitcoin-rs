from pathlib import Path
import sys
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import consensus_monitor as monitor


class WitnessEndpointTests(unittest.TestCase):
    def test_reference_and_replay_cannot_share_an_endpoint_under_different_spellings(self):
        def endpoint(url):
            return {"url": url, "credentials": "unused", "settings": {}}

        config = {"local": endpoint("http://127.0.0.1:8332"), "reference": endpoint("http://[::1]")}
        for alias in ("http://[0:0:0:0:0:0:0:1]", "http://[::1]:80"):
            with self.subTest(alias=alias):
                config["reference_replay"] = endpoint(alias)
                with self.assertRaises(ValueError):
                    monitor.configured_witnesses(config)
        config["reference_replay"] = endpoint("http://[::1]:8332")
        _, reference = monitor.configured_witnesses(config)
        self.assertEqual(reference.replay.port, 8332)
