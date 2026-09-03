import unittest
import pandas as pd
import numpy as np
from src.data.windowing import slice_into_windows, create_sequences_and_targets


class TestWindowing(unittest.TestCase):
    def setUp(self):
        # Generate 100 seconds of synthetic network flows
        base_time = pd.Timestamp("2026-09-04 10:00:00")
        timestamps = [base_time + pd.Timedelta(seconds=i * 0.5) for i in range(200)]
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

    def test_windowing_stride_and_overlap(self):
        windows = slice_into_windows(self.df, window_size_sec=5.0, stride_sec=2.5, skip_empty=False)
        self.assertGreater(len(windows), 10)

        # First window: 10:00:00 to 10:00:05
        # Second window: 10:00:02.5 to 10:00:07.5
        w0 = windows[0]
        w1 = windows[1]
        self.assertEqual(w0["end_time"] - w0["start_time"], pd.Timedelta(seconds=5.0))
        self.assertEqual(w1["start_time"] - w0["start_time"], pd.Timedelta(seconds=2.5))

    def test_no_target_leakage(self):
        """CRITICAL: Target window MUST NOT overlap with the last input window."""
        windows = slice_into_windows(self.df, window_size_sec=5.0, stride_sec=2.5)
        samples = create_sequences_and_targets(windows, seq_len=10, k_horizon=4, window_size_sec=5.0)

        self.assertGreater(len(samples), 0)
        for s in samples:
            last_input_end = s["last_input_end"]
            first_target_start = s["first_target_start"]

            # Target start time must be >= last input end time
            self.assertGreaterEqual(
                first_target_start,
                last_input_end,
                f"Target leakage detected! Target starts at {first_target_start} before input ended at {last_input_end}"
            )


if __name__ == "__main__":
    unittest.main()
