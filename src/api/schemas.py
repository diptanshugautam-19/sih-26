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
    action: str = Field(..., description="'isolate_host' or 'block_port'")
    target: str = Field(..., description="IP address (e.g. '10.0.0.5') or port number (e.g. '445')")
    current_risk: Optional[float] = Field(None, description="Baseline risk probability before action")


class CounterfactualResponse(BaseModel):
    action: str
    target: str
    original_risk: float
    recalculated_risk: float
    risk_reduction: float
    stage_after_action: str
