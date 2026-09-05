import unittest
import pandas as pd
from src.labels.window_labels import aggregate_window_mitre_label, extract_stage_transitions


class TestWindowLabels(unittest.TestCase):
    def test_aggregate_window_mitre_label_sparse_attack(self):
        # 95 benign rows, 5 lateral movement rows (stage 4)
        df = pd.DataFrame({
            "mitre_stage_id": [0] * 95 + [4] * 5,
            "mitre_confidence": [0.95] * 95 + [0.85] * 5,
        })
        stage_id, stage_name, conf, is_mal = aggregate_window_mitre_label(df)
        # Infiltration must NOT be washed out by benign majority!
        self.assertEqual(stage_id, 4)
        self.assertEqual(stage_name, "Lateral Movement")
        self.assertTrue(is_mal)
        self.assertAlmostEqual(conf, 0.85, places=2)

    def test_aggregate_window_all_benign(self):
        df = pd.DataFrame({
            "mitre_stage_id": [0] * 50,
            "mitre_confidence": [0.98] * 50,
        })
        stage_id, stage_name, conf, is_mal = aggregate_window_mitre_label(df)
        self.assertEqual(stage_id, 0)
        self.assertEqual(stage_name, "Benign")
        self.assertFalse(is_mal)

    def test_extract_stage_transitions(self):
        seq = [1, 1, 3, 4]
        transitions = extract_stage_transitions(seq)
        self.assertEqual(transitions, [(1, 1), (1, 3), (3, 4)])


if __name__ == "__main__":
    unittest.main()
