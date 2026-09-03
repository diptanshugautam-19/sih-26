# Predictive Cyber Defence World Model

An AI World Model architecture that learns network state-transition dynamics $P(S_{t+1} \mid S_t)$ from traffic telemetry, rolls out $K$ steps ahead, and predicts infiltration likelihood and MITRE ATT&CK attack stages before compromise is completed.

## Key Highlights
- **Temporal & Structural Modelling**: GATConv (Graph Neural Network) + Temporal Transformer.
- **Explainability**: GAT attention maps and feature attributions for defender interpretability.
- **Offline & Self-Contained**: Designed for Critical Information Infrastructure with zero external cloud dependencies.
- **MITRE ATT&CK Stage Mapping**: Reconnaissance, Initial Access, Lateral Movement, C2, and Exfiltration.

## Repository Structure
Please refer to [`PROJECT_MEMORY.md`](PROJECT_MEMORY.md) for full architecture decisions, data handling rules, and system contracts.
