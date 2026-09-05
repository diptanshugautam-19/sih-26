import unittest
import torch
import pandas as pd
from src.data.graph_builder import PersistentNodeRegistry, build_graph_for_window
from src.models.worldmodel import CyberDefenceWorldModel


class TestCyberDefenceWorldModel(unittest.TestCase):
    def setUp(self):
        self.registry = PersistentNodeRegistry()
        self.model = CyberDefenceWorldModel(
            node_dim=16,
            edge_dim=16,
            memory_dim=32,
            hidden_dim=64,
            seq_len=5,
            horizon_k=4,
        )

        # Build a sequence of 5 synthetic graph snapshots
        self.seq = []
        for w in range(5):
            df = pd.DataFrame({
                "src_ip": ["192.168.1.5", "10.0.0.10"],
                "dst_ip": ["10.0.0.1", "10.0.0.2"],
                "dst_port": [445, 80],
                "payload_size": [1000 + w * 200, 500],
                "flag_syn": [True, False],
                "flag_ack": [False, True],
                "flag_rst": [False, False],
                "flag_fin": [False, False],
                "is_retransmission": [False, False],
                "ttl": [64, 64],
                "tcp_window": [65535, 65535],
            })
            snap = build_graph_for_window(df, self.registry, window_id=w)
            self.seq.append(snap)

    def test_forward_pass_outputs(self):
        preds = self.model.forward_sequence(self.seq)
        
        # Check output structure
        self.assertIn("grounded_telemetry", preds)
        self.assertIn("infiltration_prob", preds)
        self.assertIn("stage_logits", preds)
        self.assertIn("host_risks", preds)
        self.assertIn("spatial_attention", preds)

        # Check shapes
        self.assertEqual(preds["grounded_telemetry"].shape, (4, 3))
        self.assertEqual(preds["stage_logits"].shape, (7,))
        self.assertEqual(preds["host_risks"].shape[0], self.registry.size())

    def test_counterfactual_rollout(self):
        # Isolate the attacking host (192.168.1.5)
        attacker_id = self.registry.get("192.168.1.5")
        cf_preds = self.model.simulate_counterfactual(self.seq, isolated_host_id=attacker_id)
        
        self.assertIn("infiltration_prob", cf_preds)
        self.assertIsInstance(float(cf_preds["infiltration_prob"].item()), float)

    def test_mc_dropout_uncertainty(self):
        uncertainty = self.model.estimate_uncertainty_mc_dropout(self.seq, n_passes=4)
        self.assertIn("mean_probability", uncertainty)
        self.assertIn("uncertainty_std", uncertainty)
        self.assertIn("confidence_lower", uncertainty)
        self.assertIn("confidence_upper", uncertainty)

    def test_worldmodel_node_in_dim_edge_in_dim_defaults(self):
        from src.models import WorldModel
        # Test default initialization matches graph_builder (16 node features, 16 edge features)
        default_wm = WorldModel(seq_len=5, horizon_k=4)
        self.assertEqual(default_wm.node_in_dim, 16)
        self.assertEqual(default_wm.edge_in_dim, 16)
        
        # Test explicit node_in_dim and edge_in_dim kwargs
        explicit_wm = WorldModel(node_in_dim=16, edge_in_dim=16, seq_len=5, horizon_k=4)
        preds = explicit_wm.forward_sequence(self.seq)
        self.assertIn("infiltration_prob", preds)
        self.assertEqual(preds["grounded_telemetry"].shape, (4, 3))


if __name__ == "__main__":
    unittest.main()
