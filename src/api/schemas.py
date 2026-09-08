"""
src/api/schemas.py

Pydantic schemas matching the API contracts defined in PROJECT_MEMORY.md and BACKEND_SPEC.md.
"""

from __future__ import annotations
from typing import Any, Dict, List, Optional
from pydantic import BaseModel, Field


class HealthResponse(BaseModel):
    status: str = "ok"
    model_loaded: bool = False
    device: str = "cpu"
    version: str = "1.0.0"


class TimelinePoint(BaseModel):
    t: float
    infiltration_prob: float
    stage: str
    stage_conf: float


class TopFeature(BaseModel):
    name: str
    contribution: float


class FlaggedEdge(BaseModel):
    src: str
    dst: str
    attn: float


class PredictResponse(BaseModel):
    timeline: List[TimelinePoint]
    current_stage: str
    mitre_technique: str
    forecast_K: int = 4
    top_features: List[TopFeature]
    flagged_edges: List[FlaggedEdge]
    ood_score: float
    uncertainty_std: Optional[float] = None
    lead_time_seconds: Optional[float] = None


class CounterfactualRequest(BaseModel):
    action: str = Field(..., description="'isolate_host', 'block_port', 'rate_limit', 'segment_subnet', or 'honeypot_divert'")
    target: str = Field(..., description="IP address (e.g. '10.0.0.5'), port ('445'), or subnet ('10.0.0.0/24')")
    current_risk: Optional[float] = Field(None, description="Baseline risk probability before action")
    parameters: Optional[Dict[str, Any]] = Field(default_factory=dict, description="Action parameters (e.g. rate_factor)")
    business_criticality: Optional[float] = Field(0.2, description="Target host/service criticality score (0.0 to 1.0)")


class CounterfactualResponse(BaseModel):
    action: str
    target: str
    original_risk: float
    recalculated_risk: float
    risk_reduction: float
    stage_after_action: str
    baseline_trajectory: Optional[List[float]] = None
    counterfactual_trajectory: Optional[List[float]] = None
    trajectory_delta: Optional[List[float]] = None
    severed_edges_count: Optional[int] = 0
    business_impact_score: Optional[float] = 0.0
    net_defense_score: Optional[float] = 0.0
    recommendation: Optional[str] = None


class ActionRankingRequest(BaseModel):
    actions: Optional[List[CounterfactualRequest]] = None
    top_n: int = 5


class ActionRankingResponse(BaseModel):
    ranked_options: List[CounterfactualResponse]
    optimal_action: Optional[CounterfactualResponse] = None
    summary: str
