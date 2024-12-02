import unittest
from unittest.mock import patch
from scapy.packet import Packet
from src.core.packet_sniffer import PacketSniffer

class TestPacketSniffer(unittest.TestCase):
    @patch("packet_sniffer.packet_handler")
    def test_packet_handler(self, mock_handler):
        mock_packet = Packet()
        mock_packet.summary = lambda: "Mock Packet Summary"
        PacketSniffer.packet_handler(mock_packet)
        mock_handler.assert_called_with(mock_packet)

if __name__ == "__main__":
    unittest.main()
