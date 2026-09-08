"""
tests/test_counterfactual.py

Rigorous unit and integration tests for the Industry-Grade Counterfactual
Simulation Engine and its FastAPI endpoints.
"""

from __future__ import annotations
import unittest
import torch
from fastapi.testclient import TestClient

from src.data.graph_builder import NetworkGraphSnapshot
from src.models.worldmodel import CyberDefenceWorldModel
from src.models.counterfactual import (
    CounterfactualAction,
    CounterfactualEngine,
    ActionType,
    _apply_action_to_snapshot,
)
from src.api.app import create_app


class TestCounterfactualEngine(unittest.TestCase):
    def setUp(self):
        torch.manual_seed(42)
        self.num_nodes = 5
        self.node_ips = ["10.0.0.1", "10.0.0.2", "10.0.0.3", "192.168.1.10", "192.168.1.20"]

        # Create a synthetic 5-window sequence
        self.seq = []
        for t in range(5):
            edge_index = torch.tensor([
                [0, 0, 1, 2, 3],
                [1, 2, 2, 3, 4]
            ], dtype=torch.long)
            edge_attr = torch.rand((5, 16), dtype=torch.float32)
            x = torch.rand((self.num_nodes, 16), dtype=torch.float32)
            dynamics = torch.tensor([2.5, 0.75, 8.2], dtype=torch.float32)

            snap = NetworkGraphSnapshot(
                window_id=t,
                start_time=t * 2.5,
                end_time=t * 2.5 + 5.0,
                num_nodes=self.num_nodes,
                edge_index=edge_index,
                x=x,
                edge_attr=edge_attr,
                node_ips=self.node_ips,
                grounded_dynamics=dynamics,
            )
            self.seq.append(snap)

        self.model = CyberDefenceWorldModel(
            node_feat_dim=16,
            edge_feat_dim=16,
            hidden_dim=32,
            temporal_dim=32,
            k_horizon=4,
            num_stages=7,
        )
        self.model.eval()
        self.engine = CounterfactualEngine(self.model)

    def test_isolate_host_severing(self):
        snap = self.seq[0]
        action = CounterfactualAction(
            action_type=ActionType.ISOLATE_HOST,
            target="10.0.0.1"  # Node 0 has 2 outbound edges
        )
        mod_snap, severed = _apply_action_to_snapshot(snap, action)

        # Node 0 features should be zeroed
        self.assertEqual(float(mod_snap.x[0].sum().item()), 0.0)
        # 2 edges from node 0 should be severed
        self.assertEqual(severed, 2)
        self.assertEqual(mod_snap.edge_index.size(1), snap.edge_index.size(1) - 2)
        # Node 0 should not appear in edge_index
        self.assertFalse((mod_snap.edge_index[0] == 0).any())
        self.assertFalse((mod_snap.edge_index[1] == 0).any())

    def test_block_port_intervention(self):
        snap = self.seq[0]
        action = CounterfactualAction(
            action_type=ActionType.BLOCK_PORT,
            target="445"
        )
        mod_snap, severed = _apply_action_to_snapshot(snap, action)
        self.assertGreaterEqual(severed, 0)
        self.assertLessEqual(mod_snap.edge_index.size(1), snap.edge_index.size(1))

    def test_rate_limit_intervention(self):
        snap = self.seq[0]
        action = CounterfactualAction(
            action_type=ActionType.RATE_LIMIT,
            target="global",
            parameters={"rate_factor": 0.2}
        )
        mod_snap, severed = _apply_action_to_snapshot(snap, action)
        # Volume and SYN dynamics should be dampened
        self.assertLess(float(mod_snap.grounded_dynamics[1]), float(snap.grounded_dynamics[1]))

    def test_segment_subnet_intervention(self):
        snap = self.seq[0]
        # Cross edge: 2 (10.0.0.3) -> 3 (192.168.1.10)
        action = CounterfactualAction(
            action_type=ActionType.SEGMENT_SUBNET,
            target="10.0."
        )
        mod_snap, severed = _apply_action_to_snapshot(snap, action)
        self.assertGreaterEqual(severed, 1)

    def test_counterfactual_engine_evaluate(self):
        action = CounterfactualAction(
            action_type=ActionType.ISOLATE_HOST,
            target="10.0.0.1",
            business_criticality=0.3,
        )
        res = self.engine.evaluate_intervention(self.seq, action)

        self.assertEqual(res.action, "isolate_host")
        self.assertEqual(res.target, "10.0.0.1")
        self.assertGreaterEqual(res.original_risk, 0.0)
        self.assertLessEqual(res.recalculated_risk, res.original_risk)
        self.assertGreaterEqual(res.risk_reduction, 0.0)
        self.assertEqual(len(res.baseline_trajectory), 4)
        self.assertEqual(len(res.counterfactual_trajectory), 4)
        self.assertEqual(len(res.trajectory_delta), 4)
        self.assertGreater(res.severed_edges_count, 0)
        self.assertIn("reduces infiltration risk", res.recommendation)

    def test_rank_interventions(self):
        candidates = [
            CounterfactualAction(ActionType.ISOLATE_HOST, "10.0.0.1", business_criticality=0.5),
            CounterfactualAction(ActionType.BLOCK_PORT, "445", business_criticality=0.1),
            CounterfactualAction(ActionType.RATE_LIMIT, "ingress", parameters={"rate_factor": 0.1}, business_criticality=0.2),
        ]
        ranked = self.engine.rank_interventions(self.seq, candidates)
        self.assertEqual(len(ranked), 3)
        # Verify descending order by net defense score
        for i in range(len(ranked) - 1):
            self.assertGreaterEqual(ranked[i].net_defense_score, ranked[i+1].net_defense_score)

    def test_worldmodel_convenience_methods(self):
        act = CounterfactualAction(ActionType.ISOLATE_HOST, "10.0.0.1")
        res = self.model.simulate_counterfactual(self.seq, action=act)
        self.assertEqual(res.action, "isolate_host")

        # Test rank method directly on model
        ranked = self.model.rank_counterfactual_actions(self.seq)
        self.assertGreater(len(ranked), 0)


class TestCounterfactualAPI(unittest.TestCase):
    def setUp(self):
        self.app = create_app()

    def test_post_counterfactual_fallback(self):
        with TestClient(self.app) as client:
            payload = {
                "action": "isolate_host",
                "target": "10.0.0.5",
                "current_risk": 0.90,
            }
            resp = client.post("/counterfactual", json=payload)
            self.assertEqual(resp.status_code, 200)
            data = resp.json()
            self.assertEqual(data["action"], "isolate_host")
            self.assertEqual(data["target"], "10.0.0.5")
            self.assertGreater(data["risk_reduction"], 0.0)
            self.assertIn("baseline_trajectory", data)
            self.assertIn("counterfactual_trajectory", data)
            self.assertIn("recommendation", data)

    def test_post_counterfactual_rank(self):
        with TestClient(self.app) as client:
            payload = {
                "actions": [
                    {"action": "isolate_host", "target": "10.0.0.5", "business_criticality": 0.4},
                    {"action": "block_port", "target": "445", "business_criticality": 0.1},
                ],
                "top_n": 2,
            }
            resp = client.post("/counterfactual/rank", json=payload)
            self.assertEqual(resp.status_code, 200)
            data = resp.json()
            self.assertIn("ranked_options", data)
            self.assertEqual(len(data["ranked_options"]), 2)
            self.assertIn("optimal_action", data)
            self.assertIn("summary", data)


if __name__ == "__main__":
    unittest.main()
