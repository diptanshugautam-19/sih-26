"""
src/utils/io.py

I/O helper routines for checkpoints, configurations, and reports.
"""

from __future__ import annotations
import json
from pathlib import Path
from typing import Any, Dict, Union
import yaml
import torch


def load_yaml(path: Union[str, Path]) -> Dict[str, Any]:
    """Loads a YAML configuration file."""
    path = Path(path)
    with path.open("r", encoding="utf-8") as f:
        return yaml.safe_load(f)


def save_yaml(data: Dict[str, Any], path: Union[str, Path]) -> None:
    """Saves dictionary data to a YAML file."""
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8") as f:
        yaml.dump(data, f, default_flow_style=False)


def load_json(path: Union[str, Path]) -> Dict[str, Any]:
    """Loads a JSON file."""
    path = Path(path)
    with path.open("r", encoding="utf-8") as f:
        return json.load(f)


def save_json(data: Any, path: Union[str, Path], indent: int = 2) -> None:
    """Saves data to a JSON file."""
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8") as f:
        json.dump(data, f, indent=indent, default=str)


def save_checkpoint(state: Dict[str, Any], path: Union[str, Path]) -> None:
    """Saves a model training checkpoint."""
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    torch.save(state, path)


def load_checkpoint(path: Union[str, Path], map_location: str = "cpu") -> Dict[str, Any]:
    """Loads a model training checkpoint safely."""
    path = Path(path)
    return torch.load(path, map_location=map_location, weights_only=False)
