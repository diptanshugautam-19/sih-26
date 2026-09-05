import unittest
import torch
import numpy as np
import pandas as pd
from io import StringIO
import sys

from src.data.graph_builder import PersistentNodeRegistry, build_graph_for_window
from src.data.dataset import SequenceSample
from src.models.worldmodel import CyberDefenceWorldModel
from src.training.rollout import (
    rollout_k_steps,
    evaluate_rollout_dataset,
    print_rollout_report,
)


class TestRolloutEvaluation(unittest.TestCase):
    def setUp(self):
        self.registry = PersistentNodeRegistry()
        self.horizon_k = 3
        self.seq_len = 4
        self.model = CyberDefenceWorldModel(
            node_dim=16,
            edge_dim=16,
            memory_dim=32,
            hidden_dim=64,
            seq_len=self.seq_len,
            horizon_k=self.horizon_k,
        )

        self.seq = []
        for w in range(self.seq_len):
            df = pd.DataFrame({
                "src_ip": ["192.168.1.10", "10.0.0.5"],
                "dst_ip": ["10.0.0.1", "10.0.0.2"],
                "dst_port": [445, 80],
                "payload_size": [1024, 512],
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

    def test_rollout_k_steps_output_structure(self):
        result = rollout_k_steps(self.model, self.seq)
        self.assertIn("grounded_telemetry", result)
        self.assertIn("infiltration_prob", result)
        self.assertIn("stage_logits", result)
        self.assertIn("spatial_attention", result)
        self.assertFalse(result["is_counterfactual"])

        telemetry = result["grounded_telemetry"]
        self.assertEqual(telemetry.shape, (self.horizon_k, 3))
        self.assertTrue(0.0 <= result["infiltration_prob"] <= 1.0)
        self.assertEqual(result["stage_logits"].shape, (7,))

    def test_rollout_k_steps_counterfactual(self):
        host_id = self.registry.get("192.168.1.10")
        result = rollout_k_steps(self.model, self.seq, isolated_host_id=host_id)
        self.assertTrue(result["is_counterfactual"])
        self.assertIn("infiltration_prob", result)
        self.assertIsInstance(result["infiltration_prob"], float)

    def test_evaluate_rollout_dataset(self):
        mock_sample = SequenceSample(
            graph_sequence=self.seq,
            infiltration_target=0.8,
            mitre_stage_id=2,
            mitre_confidence=0.9,
            grounded_targets=torch.zeros((self.horizon_k, 3)),
            is_malicious=True,
        )
        samples = [mock_sample, mock_sample]
        metrics = evaluate_rollout_dataset(self.model, samples)

        self.assertEqual(metrics["n_samples"], 2)
        self.assertEqual(metrics["mae_per_step"].shape, (self.horizon_k, 3))
        self.assertEqual(metrics["rmse_per_step"].shape, (self.horizon_k, 3))
        self.assertIn("infil_f1", metrics)
        self.assertIn("stage_acc", metrics)

        # Test report printing doesn't crash
        old_stdout = sys.stdout
        sys.stdout = StringIO()
        try:
            print_rollout_report(metrics)
            report_text = sys.stdout.getvalue()
            self.assertIn("K-Step Rollout Evaluation Report", report_text)
        finally:
            sys.stdout = old_stdout


if __name__ == "__main__":
    unittest.main()
