import unittest
import os
import tempfile
import pandas as pd
from scapy.all import wrpcap, Ether, IP, TCP, UDP
from src.data.packet_features import parse_pcap_to_dataframe, parse_pcap_dpkt_stream


class TestPacketFeatures(unittest.TestCase):
    def setUp(self):
        # Create a temporary synthetic PCAP file with known packets
        self.tmp_dir = tempfile.TemporaryDirectory()
        self.pcap_path = os.path.join(self.tmp_dir.name, "test_synthetic.pcap")

        pkts = [
            Ether() / IP(src="192.168.1.5", dst="10.0.0.1", ttl=64) / TCP(sport=1024, dport=80, flags="S", window=8192),
            Ether() / IP(src="10.0.0.1", dst="192.168.1.5", ttl=50) / TCP(sport=80, dport=1024, flags="SA", window=65535),
            Ether() / IP(src="192.168.1.5", dst="10.0.0.1", ttl=64) / TCP(sport=1024, dport=80, flags="A"),
            Ether() / IP(src="192.168.1.5", dst="8.8.8.8", ttl=128) / UDP(sport=5353, dport=53),
        ]
        wrpcap(self.pcap_path, pkts)

    def tearDown(self):
        self.tmp_dir.cleanup()

    def test_parse_pcap_to_dataframe(self):
        df = parse_pcap_to_dataframe(self.pcap_path)
        self.assertEqual(len(df), 4)

        # Check column presence
        expected_cols = [
            "timestamp", "src_ip", "src_port", "dst_ip", "dst_port", "protocol",
            "ttl", "tcp_win", "syn", "ack"
        ]
        for col in expected_cols:
            self.assertIn(col, df.columns)

        # Verify packet 0 was SYN
        pkt0 = df.iloc[0]
        self.assertEqual(pkt0["src_ip"], "192.168.1.5")
        self.assertEqual(pkt0["dst_ip"], "10.0.0.1")
        self.assertEqual(pkt0["src_port"], 1024)
        self.assertEqual(pkt0["dst_port"], 80)
        self.assertEqual(pkt0["syn"], 1)
        self.assertEqual(pkt0["ack"], 0)
        self.assertEqual(pkt0["ttl"], 64)

        # Verify packet 1 was SYN-ACK
        pkt1 = df.iloc[1]
        self.assertEqual(pkt1["syn"], 1)
        self.assertEqual(pkt1["ack"], 1)
        self.assertEqual(pkt1["ttl"], 50)


if __name__ == "__main__":
    unittest.main()
