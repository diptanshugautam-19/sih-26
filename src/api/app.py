"""
src/api/app.py

FastAPI Application Factory for the Cyber Defence World Model.
"""

from __future__ import annotations
from contextlib import asynccontextmanager
from pathlib import Path
from typing import AsyncGenerator, Optional
import torch
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from src.api.routes import router
from src.models.worldmodel import CyberDefenceWorldModel
from src.utils.logging import get_logger

logger = get_logger("src.api.app")


def load_model_instance(
    checkpoint_path: str = "models/best_model.pt",
    device: str = "cpu",
) -> CyberDefenceWorldModel:
    """
    Loads trained CyberDefenceWorldModel checkpoint, falling back to a fresh model if not found.
    """
    model = CyberDefenceWorldModel(
        node_in_dim=16,
        edge_in_dim=16,
        memory_dim=32,
        hidden_dim=64,
        seq_len=10,
        horizon_k=4,
    ).to(device)

    ckpt_file = Path(checkpoint_path)
    if ckpt_file.exists():
        try:
            ckpt = torch.load(ckpt_file, map_location=device, weights_only=False)
            state = ckpt["model_state"] if isinstance(ckpt, dict) and "model_state" in ckpt else ckpt
            model_dict = model.state_dict()
            # Filter out mismatched shapes (e.g. legacy checkpoints before edge_in_dim=16 fix)
            compatible_dict = {
                k: v for k, v in state.items()
                if k in model_dict and v.shape == model_dict[k].shape
            }
            model_dict.update(compatible_dict)
            model.load_state_dict(model_dict)
            logger.info(f"Loaded {len(compatible_dict)}/{len(model_dict)} layers from {ckpt_file}")
        except Exception as e:
            logger.warning(f"Failed to load checkpoint weights: {e}; using initialized model.")
    else:
        logger.info("No checkpoint file found at models/best_model.pt; using initialized model.")

    model.eval()
    return model


@asynccontextmanager
async def lifespan(app: FastAPI) -> AsyncGenerator[None, None]:
    """
    Application lifespan context manager: handles startup model load and cleanup.
    """
    device = "cuda" if torch.cuda.is_available() else "cpu"
    app.state.device = device
    app.state.model = load_model_instance(device=device)
    app.state.cached_snapshots = []
    logger.info(f"FastAPI application initialized successfully on {device}.")
    yield


def create_app() -> FastAPI:
    """FastAPI application factory."""
    app = FastAPI(
        title="Predictive Cyber Defence World Model API",
        description="Offline-capable API for network state transitions, K-step rollout, MITRE ATT&CK prediction, and counterfactual simulation.",
        version="1.0.0",
        lifespan=lifespan,
    )

    # Enable CORS for local dashboards and web clients
    app.add_middleware(
        CORSMiddleware,
        allow_origins=["*"],
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
    )

    app.include_router(router)
    return app


app = create_app()
