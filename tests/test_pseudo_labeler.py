import unittest
import pandas as pd
from src.labels.pseudo_labeler import infer_pseudo_mitre_stage, annotate_dataframe_with_pseudo_labels


class TestPseudoLabeler(unittest.TestCase):
    def test_reconnaissance_heuristic(self):
        flow = {
            "src_ip": "192.168.1.50",
            "dst_ip": "10.0.0.1",
            "dst_port": 80,
            "flag_syn": True,
            "flag_ack": False,
            "payload_size": 0,
            "flag_rst": True,
        }
        stage_id, stage_name, tech, conf = infer_pseudo_mitre_stage(flow)
        self.assertEqual(stage_id, 1)
        self.assertEqual(stage_name, "Reconnaissance")
        self.assertEqual(tech, "T1595.001")
        self.assertGreaterEqual(conf, 0.7)

    def test_lateral_movement_heuristic(self):
        flow = {
            "src_ip": "10.0.0.5",
            "dst_ip": "10.0.0.22",
            "dst_port": 445,
            "flag_syn": True,
            "flag_ack": True,
            "payload_size": 512,
        }
        stage_id, stage_name, tech, conf = infer_pseudo_mitre_stage(flow)
        self.assertEqual(stage_id, 4)
        self.assertEqual(stage_name, "Lateral Movement")
        self.assertEqual(tech, "T1021.002")

    def test_credential_access_heuristic(self):
        flow = {
            "src_ip": "192.168.1.100",
            "dst_ip": "10.0.0.1",
            "dst_port": 22,
            "flag_syn": True,
            "flag_ack": True,
            "payload_size": 120,
        }
        stage_id, stage_name, tech, conf = infer_pseudo_mitre_stage(flow)
        self.assertEqual(stage_id, 3)
        self.assertEqual(stage_name, "Credential Access")


if __name__ == "__main__":
    unittest.main()
