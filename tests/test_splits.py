import unittest
from src.labels.splits import temporal_block_split, unseen_attack_split


class DummySample:
    def __init__(self, mitre_stage_id: int = 0, mitre_stage_name: str = "Benign"):
        self.mitre_stage_id = mitre_stage_id
        self.mitre_stage_name = mitre_stage_name


class TestSplits(unittest.TestCase):
    def test_temporal_block_split_basic(self):
        dataset = [DummySample() for _ in range(100)]
        train_idx, val_idx, test_idx = temporal_block_split(
            dataset, train_frac=0.7, val_frac=0.15, buffer_sequences=5
        )

        self.assertGreater(len(train_idx), 0)
        self.assertGreater(len(val_idx), 0)
        self.assertGreater(len(test_idx), 0)

        # Contiguous chronological ordering
        self.assertEqual(train_idx, sorted(train_idx))
        self.assertEqual(val_idx, sorted(val_idx))
        self.assertEqual(test_idx, sorted(test_idx))

        # Check safety buffer strictly isolates splits
        self.assertGreater(val_idx[0], train_idx[-1] + 4)
        self.assertGreater(test_idx[0], val_idx[-1] + 4)

        # No overlapping indices
        all_indices = set(train_idx) | set(val_idx) | set(test_idx)
        self.assertEqual(len(all_indices), len(train_idx) + len(val_idx) + len(test_idx))

    def test_unseen_attack_split(self):
        # 80 benign samples, 10 stage-3 (Discovery), 10 stage-6 (Exfiltration)
        samples = [DummySample(0, "Benign") for _ in range(80)]
        samples += [DummySample(3, "Discovery") for _ in range(10)]
        samples += [DummySample(6, "Exfiltration") for _ in range(10)]

        # Hold out stage 6 (Exfiltration)
        train_idx, val_idx, test_unseen_idx = unseen_attack_split(
            samples, holdout_stages=[6]
        )

        # All stage 6 samples must be in test_unseen
        self.assertEqual(len(test_unseen_idx), 10)
        for idx in test_unseen_idx:
            self.assertEqual(samples[idx].mitre_stage_id, 6)

        # No stage 6 in train or val
        for idx in train_idx:
            self.assertNotEqual(samples[idx].mitre_stage_id, 6)
        for idx in val_idx:
            self.assertNotEqual(samples[idx].mitre_stage_id, 6)


if __name__ == "__main__":
    unittest.main()
