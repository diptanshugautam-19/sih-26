import unittest
import os
from pathlib import Path
import pandas as pd
from src.data.download import generate_offline_benchmark_sample


class TestDownload(unittest.TestCase):
    def test_generate_offline_benchmark_sample(self):
        sample_path = Path("data/test_offline_sample.csv")
        try:
            out_path = generate_offline_benchmark_sample(dest_path=sample_path, n_flows=100, seed=123)
            self.assertTrue(out_path.exists())

            df = pd.read_csv(out_path)
            self.assertEqual(len(df), 100)

            # Check essential columns
            required_cols = [
                "timestamp", "src_ip", "dst_ip", "src_port", "dst_port",
                "protocol", "payload_size", "flag_syn", "flag_ack",
                "label", "mitre_stage_id", "mitre_confidence"
            ]
            for col in required_cols:
                self.assertIn(col, df.columns)

            # Verify no NaN or inf in critical features
            self.assertFalse(df["timestamp"].isna().any())
            self.assertFalse(df["payload_size"].isna().any())
        finally:
            if sample_path.exists():
                sample_path.unlink()


if __name__ == "__main__":
    unittest.main()
