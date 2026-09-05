import unittest
import pandas as pd
from src.labels.pseudo_labeler import (
    infer_pseudo_mitre_stage,
    annotate_dataframe_with_pseudo_labels,
    is_rfc1918_private_ip,
)


class TestPseudoLabeler(unittest.TestCase):
    def test_rfc1918_private_ip_full_range(self):
        # 10.x, 192.168.x, 127.x
        self.assertTrue(is_rfc1918_private_ip("10.0.0.1"))
        self.assertTrue(is_rfc1918_private_ip("192.168.1.1"))
        self.assertTrue(is_rfc1918_private_ip("127.0.0.1"))

        # 172.16.0.0 to 172.31.255.255
        self.assertTrue(is_rfc1918_private_ip("172.16.0.1"))
        self.assertTrue(is_rfc1918_private_ip("172.20.10.5"))
        self.assertTrue(is_rfc1918_private_ip("172.31.255.254"))

        # Public IPs outside range
        self.assertFalse(is_rfc1918_private_ip("172.15.0.1"))
        self.assertFalse(is_rfc1918_private_ip("172.32.0.1"))
        self.assertFalse(is_rfc1918_private_ip("8.8.8.8"))
        self.assertFalse(is_rfc1918_private_ip("1.1.1.1"))

    def test_rule_precedence(self):
        # A TCP SYN packet (flag_syn=True, flag_ack=False, payload_size=0)
        # targeting port 445 on an internal subnet is Lateral Movement, NOT generic Recon!
        flow = {
            "src_ip": "172.20.0.10",
            "dst_ip": "172.20.0.20",
            "dst_port": 445,
            "flag_syn": True,
            "flag_ack": False,
            "payload_size": 0,
        }
        stage_id, stage_name, tech, conf = infer_pseudo_mitre_stage(flow)
        self.assertEqual(stage_id, 4)
        self.assertEqual(stage_name, "Lateral Movement")

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

    def test_annotate_dataframe_with_pseudo_labels_vectorized(self):
        df = pd.DataFrame({
            "src_ip": ["172.20.0.5", "10.0.0.1", "192.168.1.10"],
            "dst_ip": ["172.20.0.10", "8.8.8.8", "10.0.0.2"],
            "dst_port": [445, 8088, 22],
            "flag_syn": [True, True, True],
            "flag_ack": [False, False, True],
            "flag_rst": [False, False, False],
            "payload_size": [0, 100, 50],
            "label": ["Benign", "Bot", "SSH-Bruteforce"],
        })
        annotated = annotate_dataframe_with_pseudo_labels(df)

        # Row 0: Explicit label "Benign" -> 0
        self.assertEqual(annotated.loc[0, "mitre_stage_id"], 0)
        # Row 1: Explicit label "Bot" -> 5 (C2)
        self.assertEqual(annotated.loc[1, "mitre_stage_id"], 5)
        # Row 2: Explicit label "SSH-Bruteforce" -> 3 (Credential Access)
        self.assertEqual(annotated.loc[2, "mitre_stage_id"], 3)


if __name__ == "__main__":
    unittest.main()
