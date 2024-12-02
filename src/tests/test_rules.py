import unittest
from src.core.rule_engine import RuleEngine

class TestRuleEngine(unittest.TestCase):
    def setUp(self):
        self.engine = RuleEngine()
        self.sample_rule = {"src": "192.168.1.100", "action": "BLOCK"}

    def test_add_rule(self):
        self.engine.add_rule(self.sample_rule)
        self.assertIn(self.sample_rule, self.engine.rules)

    def test_remove_rule(self):
        self.engine.add_rule(self.sample_rule)
        self.engine.remove_rule(self.sample_rule)
        self.assertNotIn(self.sample_rule, self.engine.rules)

    def test_check_packet_allow(self):
        packet = {"ip": {"src": "10.0.0.1"}}
        result = self.engine.check_packet(packet)
        self.assertEqual(result, "ALLOW")

    def test_check_packet_block(self):
        self.engine.add_rule(self.sample_rule)
        packet = {"ip": {"src": "192.168.1.100"}}
        result = self.engine.check_packet(packet)
        self.assertEqual(result, "BLOCK")

if __name__ == "__main__":
    unittest.main()
