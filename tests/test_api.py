"""
tests/test_api.py

Unit and integration tests for FastAPI backend endpoints:
- GET /health
- GET /metrics
- POST /counterfactual
- POST /predict
"""

import io
import unittest
import pandas as pd
from fastapi.testclient import TestClient

from src.api.app import create_app


class TestAPIEndpoints(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.app = create_app()
        cls.client = TestClient(cls.app)

    def test_health_endpoint(self):
        with TestClient(self.app) as client:
            resp = client.get("/health")
            self.assertEqual(resp.status_code, 200)
            data = resp.json()
            self.assertEqual(data["status"], "ok")
            self.assertIn("model_loaded", data)
            self.assertIn("version", data)

    def test_metrics_endpoint(self):
        with TestClient(self.app) as client:
            resp = client.get("/metrics")
            self.assertEqual(resp.status_code, 200)
            data = resp.json()
            self.assertEqual(data["status"], "ok")
            self.assertIn("benchmark_summary", data)

    def test_counterfactual_endpoint(self):
        with TestClient(self.app) as client:
            payload = {
                "action": "isolate_host",
                "target": "10.0.0.5",
                "current_risk": 0.88,
            }
            resp = client.post("/counterfactual", json=payload)
            self.assertEqual(resp.status_code, 200)
            data = resp.json()
            self.assertEqual(data["action"], "isolate_host")
            self.assertEqual(data["target"], "10.0.0.5")
            self.assertGreater(data["risk_reduction"], 0.0)

    def test_predict_endpoint_empty_file_rejected(self):
        with TestClient(self.app) as client:
            files = {"file": ("empty.csv", b"", "text/csv")}
            resp = client.post("/predict", files=files)
            self.assertEqual(resp.status_code, 400)

    def test_predict_endpoint_valid_telemetry(self):
        with TestClient(self.app) as client:
            # Create a minimal synthetic telemetry CSV with flow attributes
            df = pd.DataFrame({
                "timestamp": [100.0, 102.0, 104.0, 106.0],
                "src_ip": ["10.0.0.1", "10.0.0.2", "10.0.0.1", "10.0.0.3"],
                "dst_ip": ["192.168.1.1", "192.168.1.2", "192.168.1.1", "192.168.1.5"],
                "src_port": [45120, 45122, 45124, 45126],
                "dst_port": [80, 443, 80, 445],
                "protocol": [6, 6, 6, 6],
                "tot_fwd_pkts": [10, 15, 20, 25],
                "tot_bwd_pkts": [8, 12, 18, 22],
                "tot_len_fwd_pkts": [1000, 1500, 2000, 2500],
                "tot_len_bwd_pkts": [800, 1200, 1800, 2200],
                "flag_syn": [1, 1, 1, 1],
                "flag_ack": [1, 1, 1, 1],
                "flag_rst": [0, 0, 0, 0],
                "flag_fin": [0, 0, 0, 0],
                "flow_duration": [1.0, 1.0, 1.0, 1.0],
                "label": ["Benign", "Benign", "Benign", "Benign"],
            })
            csv_bytes = df.to_csv(index=False).encode("utf-8")
            files = {"file": ("test_flows.csv", csv_bytes, "text/csv")}

            resp = client.post("/predict", files=files)
            self.assertEqual(resp.status_code, 200)
            data = resp.json()
            self.assertIn("timeline", data)
            self.assertIn("current_stage", data)
            self.assertIn("mitre_technique", data)
            self.assertIn("ood_score", data)
            self.assertGreater(len(data["timeline"]), 0)


if __name__ == "__main__":
    unittest.main()
