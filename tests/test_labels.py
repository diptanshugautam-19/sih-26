import unittest
from src.labels.attack_mapping import map_label_to_stage, is_malicious, normalize_label

class TestAttackMapping(unittest.TestCase):
    def test_benign_labels(self):
        self.assertEqual(normalize_label(" Benign "), "benign")
        stage_id, name, tech = map_label_to_stage("Benign")
        self.assertEqual(stage_id, 0)
        self.assertEqual(name, "Benign")
        self.assertFalse(is_malicious("Benign"))

    def test_dos_labels(self):
        stage_id, name, tech = map_label_to_stage("DoS attacks-Slowloris ")
        self.assertEqual(stage_id, 2)
        self.assertEqual(name, "Initial Access")
        self.assertEqual(tech, "T1498.001")
        self.assertTrue(is_malicious("DoS attacks-Slowloris"))

    def test_infiltration_labels(self):
        stage_id, name, tech = map_label_to_stage("Infilteration")
        self.assertEqual(stage_id, 4)
        self.assertEqual(name, "Lateral Movement")
        self.assertEqual(tech, "T1021")

    def test_botnet_labels(self):
        stage_id, name, tech = map_label_to_stage("Bot")
        self.assertEqual(stage_id, 5)
        self.assertEqual(name, "Command & Control")

if __name__ == "__main__":
    unittest.main()
