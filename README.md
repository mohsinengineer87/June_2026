# PASTA-ML: A Scalable Machine Learning-Integrated Threat Modeling Framework

[![Streamlit App](https://static.streamlit.io/badges/streamlit_badge_black_white.svg)](https://your-app-name.streamlit.app)
[![Python 3.11+](https://img.shields.io/badge/python-3.11+-blue.svg)](https://www.python.org/downloads/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)

---

## 📋 Research Overview

**PASTA-ML** extends the traditional [PASTA (Process for Attack Simulation and Threat Analysis)](https://threat-modeling.com/pasta-threat-modeling/) framework with machine learning-based risk estimation and rigorous quantitative scalability evaluation — designed for **large-scale cyber-physical and distributed systems**.

This is a **hybrid approach** combining:
- **Simulation + Synthetic data** — the main 6-step PASTA-ML pipeline (reproducible, scalable, privacy-safe)
- **Real public dataset** — standalone CVE exploit-prediction classifier using the Kaggle CISA/EPSS enriched dataset (330,841 real CVEs)

### Research Problem
Existing PASTA implementations lack empirical evaluation of how data generation, vulnerability feature extraction, model training, and inference scale with growing numbers of assets and threat vectors. This framework addresses that gap with statistically rigorous benchmarks (multi-seed, 95% CI, log-log complexity fit).

---

## 🚀 Quick Start

### Option 1 — Run Locally

```bash
# 1. Clone the repository
git clone https://github.com/YOUR_USERNAME/pasta-ml-framework.git
cd pasta-ml-framework

# 2. Create a virtual environment (recommended)
python -m venv venv
source venv/bin/activate        # macOS / Linux
venv\Scripts\activate           # Windows

# 3. Install dependencies
pip install -r requirements.txt

# 4. Launch the app
streamlit run 3June2026pasta_ml_app_enhanced.py
```

The app will open automatically at `http://localhost:8501`

### Option 2 — Docker

```bash
docker build -t pasta-ml:latest .
docker run --rm -p 8501:8501 pasta-ml:latest
# Open http://localhost:8501
```

### Option 3 — GitHub Codespaces / VS Code Dev Container

Open the repository in Codespaces or VS Code with the Dev Containers extension — the environment configures and launches automatically.

### Option 4 — Streamlit Cloud (no install needed)

Click the badge at the top of this README, or visit:
`https://your-app-name.streamlit.app`

---

## 📁 Repository Structure

```
pasta-ml-framework/
│
├── 3June2026pasta_ml_app_enhanced.py  ← Main Streamlit application (all steps)
├── requirements.txt                   ← Python dependencies
├── README.md                          ← This file
├── LICENSE                            ← MIT License
├── Dockerfile                         ← Container build for reproducible deployment
├── runtime.txt                        ← Python version for Streamlit Cloud
│
└── .streamlit/
    └── config.toml                    ← Streamlit theme & server configuration
```

---

## 🔬 Framework Details

### 6-Step Research Pipeline

| Phase | Step | Description |
|-------|------|-------------|
| Phase 1 | Step 1 | Modified PASTA Framework Design |
| Phase 1 | Step 2 | System Modeling & Threat Environment Simulation |
| Phase 2 | Step 3 | Synthetic Threat Scenario Generation + Attack Path Analytics |
| Phase 2 | Step 4 | Feature Engineering, Complexity Characterization & Sensitivity Analysis |
| Phase 3 | Step 5 | Machine Learning-Based Risk Estimation (Regression) |
| Phase 3 | Step 5b | Monte-Carlo Attack Simulation + Binary Alerting Classifier |
| Phase 3 | Step 6 | Scalability & Performance Evaluation |

### Step 1 — Modified PASTA Framework Design
- Restructures the 7-stage PASTA methodology for automated, scalable analysis
- Maps each stage to quantitative model variables and ML pipeline components
- Theoretical complexity analysis: O(1) → O(N) → O(N²) → NP-hard across stages

### Step 2 — System Environment Simulation
- **7 asset types**: Cloud VM, IoT Device, Database Server, Network Device, Enterprise App, SCADA/ICS, Endpoint
- **Layered enterprise topology**: Barabási–Albert (Core), Watts–Strogatz (Distribution), Random Tree or Random Geometric (Access)
- **Node attributes**: criticality, exposure, patch_compliance, control_coverage, trust_boundary, attack_surface, reachability
- **4 graph centrality features** per node: degree, betweenness, eigenvector, clustering coefficient
- **VLAN zone mapping**: Core → VLAN30-ICS, Distribution → VLAN20-DMZ, Access → VLAN10-Enterprise
- **6 STIX 2.1-aligned threat actor profiles**

### Step 3 — Threat Scenario Generation + Attack Path Analytics
- Up to **10,000 synthetic attack scenarios** with MITRE ATT&CK ICS kill-chain sequencing
- **NetworkX directed attack graph** (BA + WS + Tree composite topology)
- **Attack path analytics**: transition probabilities, cumulative risk, lateral movement frequency, critical path identification
- CVSS scores follow **NVD 2024 severity distribution**: Critical 14%, High 34%, Medium 50%, Low 2%

### Step 4 — Feature Engineering (10 Features) + Sensitivity Analysis

| Feature | Description |
|---------|-------------|
| `asset_criticality` | Weighted CIA impact × exposure factor |
| `vuln_count_norm` | Log-normalised vulnerability count |
| `cvss_weighted_avg` | Severity-weighted average CVSS score |
| `exploitability_score` | CVSS exploitability sub-score composite |
| `attack_path_length_inv` | 1 / shortest path length (shorter = riskier) |
| `threat_likelihood` | Capability × motivation × exposure product |
| `exposure_level` | Network zone ordinal (internet=1.0 → air-gap=0.1) |
| `patch_compliance_inv` | 1 − patch compliance rate |
| `attacker_capability` | Normalised threat actor capability score |
| `control_effectiveness_inv` | 1 − security control coverage |

**Sensitivity analysis**: Monte Carlo Dirichlet weight sampling (30 iterations) + node-attribute correlation bar chart (reachability, attack_surface, trust_boundary, degree, zone)

### Step 5 — ML Risk Estimation (Regression)
- **Random Forest** + **Gradient Boosting** + Linear Regression regressors
- Baselines: Mean Dummy + transparent PASTA formula
- Evaluation: R², MAE, RMSE, MAPE, k-fold CV, grouped holdout by asset_type and attack_vector
- **SHAP TreeExplainer** beeswarm + **permutation importance**
- Prediction uncertainty intervals (RF estimator disagreement)
- Feature-family ablation study

### Step 5b — Monte-Carlo Attack Simulation + Alerting Classifier
- **ε-greedy attacker** simulation across layered topology (K independent runs)
- Per-step: transition probability, cumulative risk, MITRE ICS kill-chain tactic assignment
- Metrics: coverage ratio, attack path diversity, lateral movement frequency, MTTMg (estimated mitigation time)
- **Binary alerting classifier** (RF + Gradient Boosting) on attack vs. normal events
- Label derived from actual simulated compromise — not from the regression risk score (avoids target leakage)
- Security policy presets: Strict (0.45) / Balanced (0.60) / Permissive (0.75)

### Step 6 — Scalability Benchmarks
- **Multi-seed runs** (N seeds) with **95% confidence intervals** per metric
- **OLS log-log regression** to fit T(N) = a·Nᵏ with goodness-of-fit (R²) and 95% CI on slope k
- **Time per node-edge unit** and **overall scalability score** (0–100)
- **Strong scaling** (fixed N, vary workers) and **weak scaling** (N grows with workers)
- **Incremental update** vs. full rebuild speedup
- **Approximate betweenness centrality** — exact vs. sampled (Pearson rank correlation)
- Baseline comparisons: vanilla manual PASTA (Morana & UcedaVélez 2015) and naive O(N²)
- **Asymptotic projection** to 10⁵–10⁷ assets with 95% prediction interval

---

## 🧩 Real Data + CTI Integration

Three modes — no external tools required:

### 1. Live API Fetch (one click, no upload)
- **CISA KEV** — actively exploited CVEs from `cisa.gov`
- **FIRST EPSS** — daily exploit probability scores from `api.first.org`
- **NVD** — recent CVEs with CVSS scores from `services.nvd.nist.gov`

### 2. Kaggle Public CVE Dataset
- 330,841 real CVEs with CVSS, EPSS, CISA KEV flag, attack vectors, CIA impacts
- Download: [kaggle.com/datasets/francescomanzoni/vulnerability-management-datasets](https://www.kaggle.com/datasets/francescomanzoni/vulnerability-management-datasets)
- Upload `cve_cisa_epss_enriched_dataset.csv` → CVE exploit-prediction classifier (RF + LR)
- Target: `known_exploited` (CISA KEV flag = 1/0)

### 3. Your Own Organisation's Data
CSV uploads: `assets.csv`, `vulnerabilities.csv`, `sbom.csv`, `cti.csv`, `controls.csv`, `expert_labels.csv`, `business_impact.csv`

---

## 🏛️ Ops + Governance

- **MM-PASTA Maturity Assessment** — 5-dimension scorecard
- **FAIR Financial Risk Quantification** — ALE, control ROI
- **Model Freshness / Drift Detection** — days stale, asset churn, new CVE count
- **Risk-to-Ticket Pipeline** — Jira/ServiceNow-ready remediation backlog (P1–P4)
- **Human-AI Governance Review** — editable scenario review log
- **NIST CSF Coverage** — radar chart scoring Identify / Protect / Detect / Respond / Recover
- **CVSS v3.1 Analysis** — official formula-computed vectors using trust_boundary and attack_surface

---

## 📊 Expected Results

| Metric | Expected Range |
|--------|---------------|
| R² (Random Forest) | 0.85 – 0.97 |
| R² (Gradient Boosting) | 0.85 – 0.97 |
| MAE | < 0.5 on 0–10 scale |
| Alerting F1 (RF) | 0.80 – 0.95 |
| Pipeline Complexity k | 1.0 – 1.4 (sub-quadratic) |
| Parallel efficiency η | > 0.6 |
| Incremental speedup | ≥ 5× vs full rebuild |
| Throughput | 500 – 5,000 scenarios/s |

---

## 🛠️ Dependencies

| Package | Purpose |
|---------|---------|
| `streamlit` | Interactive web application |
| `plotly` | Interactive charts |
| `pandas` | Data manipulation |
| `numpy` | Numerical computation |
| `scikit-learn` | ML models, metrics, validation |
| `networkx` | Attack graph construction + path analysis |
| `shap` | SHAP feature explainability |
| `joblib` | Parallel computation |
| `python-docx` | Word report generation |

---

## 📚 References

1. UcedaVélez, T. & Morana, M.M. (2015). *Risk Centric Threat Modeling*. Wiley.
2. MITRE ATT&CK Framework — https://attack.mitre.org
3. NIST NVD / CVSS v3.1 — https://nvd.nist.gov/vuln-metrics/cvss
4. CISA Known Exploited Vulnerabilities — https://www.cisa.gov/known-exploited-vulnerabilities-catalog
5. FIRST EPSS — https://www.first.org/epss/
6. Lundberg, S.M. & Lee, S.I. (2017). *A Unified Approach to Interpreting Model Predictions*. NeurIPS.
7. Hagberg, A. et al. (2008). *Exploring Network Structure, Dynamics, and Function using NetworkX*.
8. Pedregosa, F. et al. (2011). *Scikit-learn: Machine Learning in Python*. JMLR, 12, 2825–2830.
9. Manzoni, F. (2024). *Vulnerability Management Datasets*. Kaggle. https://www.kaggle.com/datasets/francescomanzoni/vulnerability-management-datasets
10. Xiong, W. & Lagerström, R. (2019). Threat modeling — A systematic literature review. *Computers & Security*, 84, 53–69.

---

## 📄 License

MIT License — see [LICENSE](LICENSE) for details.

---

## 👤 Authors

**Abdul Mohsin · Dr. Sujala Shetty**
BITS Pilani — Dubai Campus

Research project for quantitative scalability evaluation of the PASTA threat modeling framework with ML integration.
Built with Streamlit · scikit-learn · NetworkX · SHAP · Plotly.
