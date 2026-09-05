import unittest
import os
import tempfile
import pandas as pd
from scapy.all import wrpcap, Ether, IP, TCP, UDP
from src.data.packet_features import extract_packet_features, add_flow_level_derived_features


class TestDeepPacketFeatures(unittest.TestCase):
    def setUp(self):
        self.tmp_dir = tempfile.TemporaryDirectory()
        self.pcap_path = os.path.join(self.tmp_dir.name, "test_retrans.pcap")

        # 1. SYN
        # 2. SYN-ACK
        # 3. Data packet (seq=100, payload="ATTACK_DATA")
        # 4. Retransmission of packet 3 (same seq=100, same payload="ATTACK_DATA")
        pkts = [
            Ether() / IP(src="10.0.0.2", dst="10.0.0.1", ttl=64) / TCP(sport=5000, dport=80, flags="S", seq=1, window=1024),
            Ether() / IP(src="10.0.0.1", dst="10.0.0.2", ttl=64) / TCP(sport=80, dport=5000, flags="SA", seq=1000, ack=2, window=1024),
            Ether() / IP(src="10.0.0.2", dst="10.0.0.1", ttl=64) / TCP(sport=5000, dport=80, flags="PA", seq=2, ack=1001) / b"ATTACK_DATA",
            Ether() / IP(src="10.0.0.2", dst="10.0.0.1", ttl=64) / TCP(sport=5000, dport=80, flags="PA", seq=2, ack=1001) / b"ATTACK_DATA",
        ]
        wrpcap(self.pcap_path, pkts)

    def tearDown(self):
        self.tmp_dir.cleanup()

    def test_retransmission_and_state(self):
        df = extract_packet_features(self.pcap_path)
        df = add_flow_level_derived_features(df)
        self.assertEqual(len(df), 4)

        # Check all required fields are present
        required_cols = [
            "tcp_seq", "tcp_ack", "tcp_window", "is_retransmission",
            "ip_frag_flag", "ttl", "flow_key", "flow_ttl_variance"
        ]
        for c in required_cols:
            self.assertIn(c, df.columns)

        # Packets 2 and 3 share the same seq within the same flow -> is_retransmission is True
        self.assertTrue(bool(df.iloc[2]["is_retransmission"]))
        self.assertTrue(bool(df.iloc[3]["is_retransmission"]))


if __name__ == "__main__":
    unittest.main()
