import unittest
from src.labels.attack_mapping import (
    map_label_to_stage,
    is_malicious,
    normalize_label,
    get_unmapped_labels,
    reset_unmapped_labels,
)


class TestAttackMapping(unittest.TestCase):
    def setUp(self):
        reset_unmapped_labels()

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

    def test_ctu13_binetflow_labels(self):
        # Real CTU-13 .binetflow label strings
        ctu_label = "flow=From-Botnet-V42-TCP-CC107-HTTP-Not-Encrypted"
        stage_id, name, tech = map_label_to_stage(ctu_label)
        self.assertEqual(stage_id, 5)
        self.assertEqual(name, "Command & Control")

        ctu_bg = "flow=Background-TCP-Established"
        stage_id_bg, name_bg, _ = map_label_to_stage(ctu_bg)
        self.assertEqual(stage_id_bg, 0)
        self.assertEqual(name_bg, "Benign")

    def test_unmapped_label_telemetry(self):
        # Unmapped novel string should default to Benign AND be recorded in telemetry
        stage_id, name, _ = map_label_to_stage("StrangeNovelAttackVariant_XYZ")
        self.assertEqual(stage_id, 0)
        self.assertEqual(name, "Benign")

        unmapped = get_unmapped_labels()
        self.assertIn("strangenovelattackvariant_xyz", unmapped)
        self.assertEqual(unmapped["strangenovelattackvariant_xyz"], 1)


if __name__ == "__main__":
    unittest.main()
