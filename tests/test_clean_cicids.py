import unittest
import pandas as pd
import numpy as np
from src.data.clean_cicids import clean_dataframe, standardize_columns


class TestCleanCicids(unittest.TestCase):
    def test_missing_ip_raises_value_error(self):
        # CSV with only ports and timestamps but no IP columns
        df_no_ip = pd.DataFrame({
            "Dst Port": [80, 443, 22],
            "Protocol": [6, 6, 6],
            "Timestamp": ["2026-09-01 10:00:00", "2026-09-01 10:00:01", "2026-09-01 10:00:02"],
            "Label": ["Benign", "Benign", "SSH-Bruteforce"],
        })
        with self.assertRaises(ValueError) as ctx:
            clean_dataframe(df_no_ip)
        self.assertIn("Missing required host endpoint", str(ctx.exception))

    def test_valid_endpoints_clean_successfully(self):
        df_valid = pd.DataFrame({
            "Src IP": ["192.168.1.100", "192.168.1.100", "10.0.0.5"],
            "Dst IP": ["10.0.0.1", "10.0.0.1", "172.16.0.10"],
            "Src Port": [54321, 54321, 44444],
            "Dst Port": [80, 80, 22],
            "Protocol": [6, 6, 6],
            "Timestamp": ["2026-09-01 10:00:00", "2026-09-01 10:00:00", "2026-09-01 10:00:02"],
            "Label": [" Benign ", " Benign ", " SSH-Bruteforce "],
            "Flow Duration": [100, 100, 250],
            "Flow Byts/s": [1000.0, 1000.0, "Infinity"],
        })
        cleaned = clean_dataframe(df_valid)
        self.assertIn("src_ip", cleaned.columns)
        self.assertIn("dst_ip", cleaned.columns)
        self.assertEqual(cleaned["label"].tolist(), ["Benign", "SSH-Bruteforce"])
        # Check deduplication dropped the duplicate row
        self.assertEqual(len(cleaned), 2)
        # Check infinite value was sanitized
        self.assertEqual(cleaned.iloc[1]["flow_byts_s"], 0.0)


if __name__ == "__main__":
    unittest.main()
