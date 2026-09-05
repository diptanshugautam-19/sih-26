import unittest
import pandas as pd
import torch
from src.data.graph_builder import PersistentNodeRegistry, build_graph_for_window


class TestGraphBuilder(unittest.TestCase):
    def setUp(self):
        self.registry = PersistentNodeRegistry()
        self.df_window = pd.DataFrame({
            "src_ip": ["192.168.1.10", "192.168.1.10", "10.0.0.5"],
            "dst_ip": ["10.0.0.1", "10.0.0.2", "10.0.0.1"],
            "dst_port": [80, 443, 22],
            "src_port": [54321, 54322, 60000],
            "protocol": [6, 6, 6],
            "payload_size": [500, 1200, 80],
            "flag_syn": [True, True, False],
            "flag_ack": [False, True, True],
            "flag_rst": [False, False, False],
            "flag_fin": [False, False, False],
            "is_retransmission": [False, False, False],
            "ttl": [64, 64, 128],
            "tcp_window": [65535, 65535, 1024],
        })

    def test_persistent_node_registry(self):
        id1 = self.registry.get_or_create("192.168.1.10")
        id2 = self.registry.get_or_create("10.0.0.1")
        id1_again = self.registry.get_or_create("192.168.1.10")
        self.assertEqual(id1, id1_again)
        self.assertNotEqual(id1, id2)

    def test_build_graph_for_window(self):
        snapshot = build_graph_for_window(self.df_window, self.registry, window_id=1)
        self.assertEqual(snapshot.num_nodes, 4)  # 4 unique IPs
        self.assertEqual(snapshot.edge_index.shape[0], 2)
        self.assertEqual(snapshot.edge_index.shape[1], 3)  # 3 distinct (src, dst) pairs
        self.assertEqual(snapshot.x.shape[0], 4)
        self.assertEqual(snapshot.x.shape[1], 16)
        self.assertEqual(snapshot.edge_attr.shape[1], 16)

        # Grounded dynamics target check
        self.assertEqual(snapshot.grounded_dynamics.shape[0], 3)
        self.assertGreater(snapshot.grounded_dynamics[2], 0.0)  # log bytes > 0


if __name__ == "__main__":
    unittest.main()
