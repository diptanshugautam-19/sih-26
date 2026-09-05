import unittest
import pandas as pd
import numpy as np
from src.data.flow_features import aggregate_packets_to_flows, canonical_flow_id


class TestFlowFeatures(unittest.TestCase):
    def setUp(self):
        # 4 packets between 192.168.1.10:50000 and 10.0.0.1:80
        # 2 forward packets, 2 reverse packets
        self.df_packets = pd.DataFrame({
            "timestamp": [100.0, 100.1, 100.3, 100.6],
            "src_ip": ["192.168.1.10", "10.0.0.1", "192.168.1.10", "10.0.0.1"],
            "dst_ip": ["10.0.0.1", "192.168.1.10", "10.0.0.1", "192.168.1.10"],
            "src_port": [50000, 80, 50000, 80],
            "dst_port": [80, 50000, 80, 50000],
            "protocol": [6, 6, 6, 6],
            "payload_size": [100.0, 500.0, 200.0, 1000.0],
            "flag_syn": [1, 1, 0, 0],
            "flag_ack": [0, 1, 1, 1],
            "flag_rst": [0, 0, 0, 0],
            "flag_fin": [0, 0, 0, 0],
            "is_retransmission": [0, 0, 0, 0],
            "label": ["Benign", "Benign", "Benign", "Benign"],
        })

    def test_canonical_flow_id(self):
        key1, tuple1 = canonical_flow_id("192.168.1.10", 50000, "10.0.0.1", 80, 6)
        key2, tuple2 = canonical_flow_id("10.0.0.1", 80, "192.168.1.10", 50000, 6)
        self.assertEqual(key1, key2)
        self.assertEqual(tuple1, tuple2)

    def test_aggregate_packets_to_flows(self):
        flows = aggregate_packets_to_flows(self.df_packets)
        self.assertEqual(len(flows), 1)

        flow = flows.iloc[0]
        self.assertEqual(flow["tot_pkts"], 4)
        self.assertAlmostEqual(flow["flow_duration"], 0.6, places=4)
        self.assertEqual(flow["tot_bytes"], 1800.0)

        # Forward & backward packets
        self.assertEqual(flow["tot_fwd_pkts"] + flow["tot_bwd_pkts"], 4)
        self.assertEqual(flow["tot_fwd_bytes"] + flow["tot_bwd_bytes"], 1800.0)

        # Bidirectional ratio
        self.assertGreater(flow["bidi_ratio"], 0.0)
        self.assertLess(flow["bidi_ratio"], 1.0)

        # Inter-arrival times
        self.assertGreater(flow["flow_iat_mean"], 0.0)
        self.assertAlmostEqual(flow["flow_iat_max"], 0.3, places=4)

        # Flag aggregation
        self.assertEqual(flow["flag_syn"], 2.0)
        self.assertEqual(flow["flag_ack"], 3.0)


if __name__ == "__main__":
    unittest.main()
