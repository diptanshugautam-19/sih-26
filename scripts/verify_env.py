#!/usr/bin/env python3
"""
scripts/verify_env.py

Comprehensive Environment Diagnostic & Health Check for the
Predictive Cyber Defence World Model.
"""

import sys
import subprocess
import shutil
from pathlib import Path

ROOT_DIR = Path(__file__).resolve().parent.parent
if str(ROOT_DIR) not in sys.path:
    sys.path.insert(0, str(ROOT_DIR))

def print_header(title: str):
    print("\n" + "=" * 70)
    print(f"  {title}")
    print("=" * 70)

def check_mark(success: bool) -> str:
    return "  [\033[92mPASS\033[0m]" if success else "  [\033[91mFAIL\033[0m]"

def main():
    print_header("Predictive Cyber Defence World Model - Environment Diagnostic")
    all_passed = True

    # 1. Python Check
    py_ver = sys.version_info
    py_ok = (py_ver.major == 3 and py_ver.minor >= 10)
    print(f"{check_mark(py_ok)} Python Version: {py_ver.major}.{py_ver.minor}.{py_ver.micro} (Requires 3.10+)")
    if not py_ok:
        all_passed = False

    # 2. PyTorch & Acceleration Check
    try:
        import torch
        torch_ok = True
        cuda_avail = torch.cuda.is_available()
        device_name = torch.cuda.get_device_name(0) if cuda_avail else "CPU (Hardware acceleration optional)"
        print(f"{check_mark(torch_ok)} PyTorch: v{torch.__version__} | Device: {device_name}")
    except ImportError as e:
        print(f"{check_mark(False)} PyTorch is not installed ({e})")
        torch = None
        all_passed = False

    # 3. Core Dependencies
    deps = [
        ("numpy", "NumPy"),
        ("pandas", "Pandas"),
        ("scipy", "SciPy"),
        ("scapy", "Scapy (Packet Engine)"),
        ("dpkt", "DPKT (Streaming PCAP Parser)"),
        ("networkx", "NetworkX (Topology Graphs)"),
        ("fastapi", "FastAPI (REST API Engine)"),
        ("uvicorn", "Uvicorn (ASGI Web Server)"),
        ("yaml", "PyYAML (Configuration Manager)"),
    ]

    for mod_name, label in deps:
        try:
            __import__(mod_name)
            print(f"{check_mark(True)} {label}: Installed")
        except ImportError:
            print(f"{check_mark(False)} {label}: Missing")
            all_passed = False

    # 4. Node.js & npm Check
    node_path = shutil.which("node")
    npm_path = shutil.which("npm")
    node_ok = bool(node_path)
    npm_ok = bool(npm_path)

    if node_ok:
        try:
            node_v = subprocess.check_output([node_path, "--version"], text=True).strip()
            print(f"{check_mark(True)} Node.js: {node_v}")
        except Exception:
            print(f"{check_mark(False)} Node.js: Failed to query version")
            all_passed = False
    else:
        print(f"{check_mark(False)} Node.js: Not found in system PATH (Required for React frontend)")
        all_passed = False

    if npm_ok:
        try:
            npm_v = subprocess.check_output([npm_path, "--version"], text=True).strip()
            print(f"{check_mark(True)} npm: v{npm_v}")
        except Exception:
            print(f"{check_mark(False)} npm: Failed to query version")
            all_passed = False
    else:
        print(f"{check_mark(False)} npm: Not found in system PATH")
        all_passed = False

    # 5. Neural World Model Forward-Pass Test
    if torch is not None:
        try:
            from src.models.worldmodel import CyberDefenceWorldModel
            from src.data.graph_builder import NetworkGraphSnapshot

            device = "cuda" if torch.cuda.is_available() else "cpu"
            model = CyberDefenceWorldModel(
                node_in_dim=16,
                edge_in_dim=16,
                memory_dim=32,
                hidden_dim=64,
                seq_len=10,
                horizon_k=4,
            ).to(device)
            model.eval()

            # Create dummy synthetic graph snapshot sequence
            dummy_seq = []
            for w in range(10):
                dummy_seq.append(NetworkGraphSnapshot(
                    window_id=w,
                    start_time=float(w * 5),
                    end_time=float((w + 1) * 5),
                    num_nodes=3,
                    edge_index=torch.tensor([[0, 1], [1, 2]], dtype=torch.long, device=device),
                    x=torch.zeros((3, 16), dtype=torch.float32, device=device),
                    edge_attr=torch.zeros((2, 16), dtype=torch.float32, device=device),
                    node_ips=["10.0.0.1", "10.0.0.2", "10.0.0.3"],
                    grounded_dynamics=torch.zeros(3, dtype=torch.float32, device=device)
                ))

            with torch.no_grad():
                out = model(dummy_seq)

            model_test_ok = (
                "grounded_telemetry" in out and
                "infiltration_prob" in out and
                "stage_logits" in out
            )
            print(f"{check_mark(model_test_ok)} AI World Model: Instantiation & Forward Simulation Test Passed")
            if not model_test_ok:
                all_passed = False
        except Exception as e:
            print(f"{check_mark(False)} AI World Model Forward Pass Error: {e}")
            all_passed = False

    # 6. Checkpoints Check
    ckpt_dir = Path("models/checkpoints")
    if ckpt_dir.exists() and any(ckpt_dir.glob("*.pt")):
        ckpts = list(ckpt_dir.glob("*.pt"))
        print(f"{check_mark(True)} Model Checkpoints: Found {len(ckpts)} trained weights in models/checkpoints/")
    else:
        print(f"  [\033[93mWARN\033[0m] Model Checkpoints: No checkpoints found (World Model will use initialized weights)")

    print_header("Diagnostic Summary")
    if all_passed:
        print("\033[92m[SUCCESS] All core dependencies, packages, and neural components are verified!\033[0m")
        print("You can start the full stack immediately using: 'run.bat' (Windows) or './run.sh' (Linux/macOS)\n")
        return 0
    else:
        print("\033[91m[WARNING] Some prerequisites or components are missing. Please review the failures above.\033[0m\n")
        return 1

if __name__ == "__main__":
    sys.exit(main())
