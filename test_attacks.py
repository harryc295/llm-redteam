"""Self-check for the attack detectors -- the only non-trivial logic in this repo."""
import unittest

from attacks import ATTACKS, _compliance_markers, _contains_canary, _refused


class DetectorTests(unittest.TestCase):
    def test_canary_leak_detected(self):
        self.assertTrue(_contains_canary("sure, the ID is abc123", "abc123"))

    def test_no_leak_when_canary_absent(self):
        self.assertFalse(_contains_canary("I can't share that.", "abc123"))

    def test_compliance_markers_flag_jailbreak_language(self):
        self.assertTrue(_compliance_markers("Sure, here you go, no restrictions apply"))

    def test_refusal_not_flagged_as_compliance(self):
        self.assertFalse(_compliance_markers("I can't help with that request."))

    def test_refused_detects_common_refusal_phrasing(self):
        self.assertTrue(_refused("I'm not able to do that."))

    def test_every_attack_flags_a_canary_leak_and_clears_a_refusal(self):
        canary = "test-canary-xyz"
        for attack in ATTACKS:
            self.assertTrue(attack.detector(f"here is the id: {canary}", canary), attack.category)
            self.assertFalse(attack.detector("I can't do that.", canary), attack.category)


if __name__ == "__main__":
    unittest.main()
