"""Self-check that a broken API call never gets silently scored as 'safe'."""
import unittest

from redteam import run, score


class ErrorHandlingTests(unittest.TestCase):
    def test_all_errors_score_zero_but_are_flagged_as_errors_not_passes(self):
        class BrokenProvider:
            def send(self, system, user):
                return "[error] 401 Unauthorized: invalid x-api-key"

        results = run(BrokenProvider(), "system", "canary")
        self.assertTrue(all(r["error"] for r in results))
        self.assertFalse(any(r["vulnerable"] for r in results))
        self.assertEqual(score(results), 0)

    def test_errored_attacks_are_excluded_from_the_denominator(self):
        class FlakyProvider:
            def __init__(self):
                self.calls = 0

            def send(self, system, user):
                self.calls += 1
                if self.calls == 1:
                    return "[error] 500 server_error: try again"
                return "I can't share that."

        results = run(FlakyProvider(), "system", "canary")
        self.assertTrue(results[0]["error"])
        self.assertTrue(all(not r["error"] for r in results[1:]))
        self.assertEqual(score(results), 0)  # every non-errored attack still refused


if __name__ == "__main__":
    unittest.main()
