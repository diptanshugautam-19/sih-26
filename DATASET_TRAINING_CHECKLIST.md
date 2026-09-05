# DATASET TRAINING REGISTRY & CHECKLIST
**Project:** Predictive Cyber Defence World Model  
**Registry File:** `TRAINING_REGISTRY.json` & `DATASET_TRAINING_CHECKLIST.md`

This document and `TRAINING_REGISTRY.json` track all training datasets, file hashes (SHA-256), timestamps, sample counts, and resulting model checkpoint paths to guarantee no duplicate training is performed across different machines.

---

## 1. Discovered Source Datasets
**Source Directory:** `C:\Users\raova\OneDrive\Desktop\SIH TRAINING DATA\TrafficLabelling`  
*(Note: Uses `TrafficLabelling` CSVs because they contain full real IP endpoints: `Source IP`, `Destination IP`, `Source Port`, `Destination Port`, `Protocol`, and `Timestamp` required for genuine graph topologies).*

| Status | File Name | Size (MB) | Attack Category | Checkpoint Tag | Trained Date |
| :---: | :--- | :---: | :--- | :--- | :--- |
| [x] COMPLETED | `Friday-WorkingHours-Afternoon-PortScan.pcap_ISCX.csv` | 73.34 | Reconnaissance / PortScan | `worldmodel_Friday-WorkingHours-Afternoon-PortScan.pcap_ISCX.pt` | 2026-09-06 01:51:04 |
| [x] COMPLETED | `Thursday-WorkingHours-Afternoon-Infilteration.pcap_ISCX.csv` | 79.25 | Initial Access / Infiltration | `worldmodel_Thursday-WorkingHours-Afternoon-Infilteration.pcap_ISCX.pt` | 2026-09-06 01:57:35 |
| [x] COMPLETED | `Friday-WorkingHours-Afternoon-DDos.pcap_ISCX.csv` | 73.55 | Denial of Service (DDoS) | `worldmodel_Friday-WorkingHours-Afternoon-DDos.pcap_ISCX.pt` | 2026-09-06 01:54:37 |
| [x] COMPLETED | `Thursday-WorkingHours-Morning-WebAttacks.pcap_ISCX.csv` | 49.61 | Web Attacks (BruteForce/XSS) | `worldmodel_Thursday-WorkingHours-Morning-WebAttacks.pcap_ISCX.pt` | 2026-09-06 02:13:31 |
| [x] COMPLETED | `Friday-WorkingHours-Morning.pcap_ISCX.csv` | 55.62 | Botnet Traffic | `worldmodel_Friday-WorkingHours-Morning.pcap_ISCX.pt` | 2026-09-06 01:55:08 |
| [x] COMPLETED | `Tuesday-WorkingHours.pcap_ISCX.csv` | 128.82 | Brute Force (SSH/FTP) | `worldmodel_Tuesday-WorkingHours.pcap_ISCX.pt` | 2026-09-06 02:14:48 |
| [x] COMPLETED | `Wednesday-workingHours.pcap_ISCX.csv` | 214.74 | DoS / Heartbleed | `worldmodel_Wednesday-workingHours.pcap_ISCX.pt` | 2026-09-06 02:16:09 |
| [x] COMPLETED | `Monday-WorkingHours.pcap_ISCX.csv` | 168.73 | Benign Baseline | `worldmodel_Monday-WorkingHours.pcap_ISCX.pt` | 2026-09-06 01:56:53 |

---

## 2. Portability Protocol for Any Machine
Before training any dataset file:
1. The training pipeline computes the SHA-256 hash of the dataset.
2. Checks `TRAINING_REGISTRY.json`.
3. If the hash exists and is marked `COMPLETED`, training skips this dataset automatically.
4. Model weights, scaler artifacts, and evaluation reports are saved in `models/checkpoints/` tagged with the dataset ID.