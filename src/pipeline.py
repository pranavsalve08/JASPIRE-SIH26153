from __future__ import annotations
import argparse, json
from pathlib import Path
import numpy as np
from sklearn.preprocessing import StandardScaler
from .demo_data import generate_demo_flows
from .features import FEATURE_COLUMNS, build_network_states, make_sequences
from .ingestion import read_csv, read_pcap, normalise_flows
from .mitre import map_attack_stage
from .models import train_lstm, train_baseline, permutation_importance, save_artifacts

ROOT=Path(__file__).resolve().parents[1]; ARTIFACTS=ROOT/"artifacts"

def run_training(flows, data_source="Local flow data"):
    states=build_network_states(flows); x,y=make_sequences(states); split=max(1,int(len(x)*.75))
    if len(np.unique(y[:split]))<2 or len(np.unique(y[split:]))<2:
        raise ValueError("Training and later test periods both need attack and benign windows.")
    scaler=StandardScaler().fit(x[:split].reshape(-1,x.shape[-1]))
    xs=scaler.transform(x.reshape(-1,x.shape[-1])).reshape(x.shape).astype(np.float32)
    model,lstm_metrics=train_lstm(xs[:split],y[:split],xs[split:],y[split:])
    baseline,baseline_metrics=train_baseline(xs[:split],y[:split],xs[split:],y[split:])
    importance=permutation_importance(model,xs[split:],y[split:],FEATURE_COLUMNS)
    lookback=8; latest=states[FEATURE_COLUMNS].to_numpy(dtype=np.float32)[-lookback:]
    if len(latest)<lookback: raise ValueError("Not enough recent network windows to forecast.")
    import torch
    with torch.no_grad(): probability=float(torch.sigmoid(model(torch.tensor(scaler.transform(latest).reshape(1,lookback,-1),dtype=torch.float32)))[0])
    current=states.iloc[-1][FEATURE_COLUMNS].to_dict()
    metadata={"feature_columns":FEATURE_COLUMNS,"lookback":lookback,"window_seconds":60,"data_source":data_source,"lstm_metrics":lstm_metrics,"baseline_metrics":baseline_metrics,"note":"Time-held-out metrics; synthetic-demo scores are not real-world performance."}
    save_artifacts(ARTIFACTS,model,scaler,baseline,metadata)
    (ARTIFACTS/"feature_importance.json").write_text(json.dumps(importance,indent=2),encoding="utf-8")
    forecast={"progression_probability":round(probability,4),"current_state":current,"mitre_hypotheses":map_attack_stage(probability,current),"disclaimer":"Forecast and ATT&CK mapping require analyst validation."}
    (ARTIFACTS/"latest_forecast.json").write_text(json.dumps(forecast,indent=2,default=str),encoding="utf-8")
    print(json.dumps({"windows":len(states),"sequences":len(x),**metadata,"latest_forecast":forecast},indent=2))

def main():
    parser=argparse.ArgumentParser(description="Train the SIH26153 offline MVP")
    group=parser.add_mutually_exclusive_group(required=True)
    group.add_argument("--csv"); group.add_argument("--pcap"); group.add_argument("--make-demo-data",action="store_true")
    parser.add_argument("--train",action="store_true"); args=parser.parse_args()
    if not args.train: parser.error("Pass --train to train and write model artifacts.")
    if args.make_demo_data:
        flows=normalise_flows(generate_demo_flows()); (ROOT/"data").mkdir(exist_ok=True); flows.to_csv(ROOT/"data/synthetic_flows.csv",index=False); source="Synthetic demo flows"
    elif args.csv: flows=read_csv(args.csv); source=f"CSV: {Path(args.csv).name}"
    else: flows=read_pcap(args.pcap); source=f"PCAP: {Path(args.pcap).name}"
    run_training(flows,source)

if __name__=="__main__": main()
