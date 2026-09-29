# JASPIRE — SIH26153 Network Attack Forecasting MVP

JASPIRE is an offline prototype that turns network flow data into rolling network states and estimates attack progression risk for the next time window. It supports analyst prioritisation; it does not confirm intrusions, attribute actors, or block traffic.

## Includes
- CSV flow ingestion and optional PCAP extraction
- Time-window network features and a temporal LSTM forecaster with Logistic Regression baseline
- Next-window progression risk, evidence importance, and heuristic MITRE ATT&CK review hypotheses
- Local Streamlit dashboard and synthetic demo data

## Quick start
Install Python 3.10+, then run:

    python -m venv .venv
    # Activate the environment for your platform
    python -m pip install -r requirements.txt
    python -m src.pipeline --make-demo-data --train
    python -m streamlit run app.py

Use labelled flows with both attack and benign periods to train and evaluate. Example: `python -m src.pipeline --csv /path/to/flows.csv --train`. PCAP extraction requires Scapy: `python -m pip install scapy`.

## Limitations
Demo labels and scores are synthetic and are not evidence of real-world accuracy. Evaluation should use representative, time-ordered data and a later held-out period. ATT&CK mappings are analyst hypotheses, not confirmed techniques. The MVP is offline and not production-ready.

## SIH product and business plan
See [docs/SIH_PRODUCT_AND_BUSINESS.md](docs/SIH_PRODUCT_AND_BUSINESS.md) for feasibility, deployment scale, indicative costs, revenue options, ecosystem, and a consistent presentation narrative.
