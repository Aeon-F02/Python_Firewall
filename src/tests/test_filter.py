import unittest
from unittest.mock import patch
from src.core.packet_filter import PacketFilter

class TestPacketFilter(unittest.TestCase):
    def setUp(self):
        self.filter = PacketFilter()
        self.sample_packet = {"summary": lambda: "Test Packet", "ip": {"src": "192.168.1.100"}}

    @patch("packet_filter.RuleEngine.check_packet")
    def test_filter_packet_allow(self, mock_check_packet):
        mock_check_packet.return_value = "ALLOW"
        result = self.filter.filter_packet(self.sample_packet)
        self.assertTrue(result)

    @patch("packet_filter.RuleEngine.check_packet")
    def test_filter_packet_block(self, mock_check_packet):
        mock_check_packet.return_value = "BLOCK"
        result = self.filter.filter_packet(self.sample_packet)
        self.assertFalse(result)

if __name__ == "__main__":
    unittest.main()
