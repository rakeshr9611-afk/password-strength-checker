import os
import sys
import unittest
from unittest import mock

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

import pwcheck  # noqa: E402


class ScoreTests(unittest.TestCase):
    def test_common_password_is_very_weak(self):
        score, label, _, weaknesses = pwcheck.score_password("password")
        self.assertEqual(score, 0)
        self.assertEqual(label, "Very weak")
        self.assertTrue(any("common" in w for w in weaknesses))

    def test_leetspeak_common_password_detected(self):
        self.assertEqual(pwcheck.score_password("P@ssw0rd")[0], 0)

    def test_long_random_password_is_very_strong(self):
        score, label, bits, weaknesses = pwcheck.score_password("vT7#qLz!9mWx$Rk2pE")
        self.assertEqual(score, 4)
        self.assertGreater(bits, 100)
        self.assertEqual(weaknesses, [])

    def test_sequences_detected(self):
        self.assertTrue(pwcheck.has_sequence("xxabcdxx"))
        self.assertTrue(pwcheck.has_sequence("Qwerty!!"))
        self.assertTrue(pwcheck.has_sequence("pass9876"))
        self.assertFalse(pwcheck.has_sequence("vT7#qLz!"))

    def test_entropy_of_empty_password(self):
        self.assertEqual(pwcheck.entropy_bits(""), 0.0)


class BreachTests(unittest.TestCase):
    def _fake_response(self, body):
        resp = mock.MagicMock()
        resp.read.return_value = body.encode()
        resp.__enter__.return_value = resp
        return resp

    def test_pwned_count_matches_suffix(self):
        # SHA-1("password") = 5BAA61E4C9B93F3F0682250B6CF8331B7EE68FD8
        body = "1E4C9B93F3F0682250B6CF8331B7EE68FD8:9545824\nABCDEF:1"
        with mock.patch("urllib.request.urlopen", return_value=self._fake_response(body)) as m:
            self.assertEqual(pwcheck.pwned_count("password"), 9545824)
            # Only the 5-char prefix is sent.
            self.assertTrue(m.call_args[0][0].full_url.endswith("/5BAA6"))

    def test_pwned_count_not_found(self):
        with mock.patch("urllib.request.urlopen", return_value=self._fake_response("ABCDEF:3")):
            self.assertEqual(pwcheck.pwned_count("password"), 0)


if __name__ == "__main__":
    unittest.main()
