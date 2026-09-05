import unittest
import pandas as pd
import numpy as np
from src.data.windowing import WindowConfig, make_input_windows, assign_rows_to_windows, build_sequences


class TestWindowing(unittest.TestCase):
    def setUp(self):
        # Generate 100 seconds of synthetic network flows
        base_time = pd.Timestamp("2026-09-04 10:00:00").timestamp()
        timestamps = [base_time + i * 0.5 for i in range(200)]
        labels = ["Benign"] * 160 + ["DoS attacks-Slowloris"] * 40

        self.df = pd.DataFrame({
            "timestamp": timestamps,
            "src_ip": ["192.168.1.10"] * 200,
            "src_port": [12345] * 200,
            "dst_ip": ["10.0.0.1"] * 200,
            "dst_port": [80] * 200,
            "protocol": [6] * 200,
            "label": labels
        })
        self.cfg = WindowConfig(window_size=5.0, stride=2.5, seq_len=10, horizon_k=4)

    def test_windowing_stride_and_overlap(self):
        t_min = float(self.df["timestamp"].min())
        t_max = float(self.df["timestamp"].max())
        input_windows = make_input_windows(t_min, t_max, self.cfg)
        self.assertGreater(len(input_windows), 10)

        # Window 0 vs Window 1
        w0_start = input_windows.loc[0, "start"]
        w0_end = input_windows.loc[0, "end"]
        w1_start = input_windows.loc[1, "start"]
        self.assertAlmostEqual(w0_end - w0_start, 5.0)
        self.assertAlmostEqual(w1_start - w0_start, 2.5)

    def test_no_target_leakage(self):
        """CRITICAL: Target window MUST NOT overlap with the last input window."""
        t_min = float(self.df["timestamp"].min())
        t_max = float(self.df["timestamp"].max())
        input_windows = make_input_windows(t_min, t_max, self.cfg)
        sequences = build_sequences(input_windows, self.cfg)

        self.assertGreater(len(sequences), 0)
        for s in sequences:
            last_input_end = s["input_end"]
            target_windows = s["target_windows"]
            first_target_start = float(target_windows.loc[0, "start"])

            # Target start time must be >= last input end time
            self.assertGreaterEqual(
                first_target_start,
                last_input_end,
                f"Target leakage detected! Target starts at {first_target_start} before input ended at {last_input_end}"
            )


if __name__ == "__main__":
    unittest.main()
