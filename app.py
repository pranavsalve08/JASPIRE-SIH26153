from pathlib import Path
import json
import numpy as np
import pandas as pd
import streamlit as st
import torch
from src.features import FEATURE_COLUMNS, build_network_states
from src.ingestion import normalise_flows
from src.mitre import map_attack_stage
from src.models import load_lstm

ROOT=Path(__file__).parent; ARTIFACTS=ROOT/"artifacts"
st.set_page_config(page_title="JASPIRE | SIH26153",page_icon="🛡️",layout="wide")
st.title("JASPIRE | Network attack forecasting")
st.caption("SIH26153 prototype • offline analyst decision support")
st.info("Forecasts estimate possible next-window progression. They do not confirm an intrusion; validate ATT&CK hypotheses with surrounding evidence.")

def read_json(name):
    path=ARTIFACTS/name
    return json.loads(path.read_text(encoding="utf-8")) if path.exists() else None

forecast=read_json("latest_forecast.json"); metadata=read_json("metadata.json"); importance=read_json("feature_importance.json")
if not all((forecast,metadata,importance)):
    st.warning("Train the local demo first: python -m src.pipeline --make-demo-data --train")
    st.stop()

prob=float(forecast["progression_probability"]); state=forecast["current_state"]
level="High" if prob>=.65 else "Moderate" if prob>=.35 else "Low"
col1,col2,col3=st.columns(3)
col1.metric("Next-window progression estimate",f"{prob:.1%}",level)
col2.metric("Flows in latest window",int(state.get("flow_count",0)))
col3.metric("Unique sources",int(state.get("unique_sources",0)))

overview,evidence,evaluation,upload=st.tabs(["Overview","Evidence","Evaluation","Forecast a CSV"])
with overview:
    st.subheader("ATT&CK-oriented analyst hypotheses")
    for item in forecast["mitre_hypotheses"]: st.write(f"**{item['stage']}** — {item['technique']}: {item['reason']}")
    st.subheader("Latest network state"); st.dataframe(pd.DataFrame([state]),use_container_width=True,hide_index=True)
with evidence:
    st.subheader("Permutation feature importance")
    chart=pd.DataFrame(importance).sort_values("importance").set_index("feature"); st.bar_chart(chart)
    st.caption("Small or negative values can occur on limited test data.")
with evaluation:
    st.subheader("Time-held-out metrics")
    st.dataframe(pd.DataFrame([{"Model":"LSTM",**metadata["lstm_metrics"]},{"Model":"Logistic Regression",**metadata["baseline_metrics"]}]),use_container_width=True,hide_index=True)
    st.warning(metadata.get("note","Validate with representative time-ordered data."))
with upload:
    st.subheader("Score the latest window of a flow CSV")
    file=st.file_uploader("Choose flow CSV",type=["csv"])
    if file:
        try:
            flows=normalise_flows(pd.read_csv(file,low_memory=False)); states=build_network_states(flows,metadata["window_seconds"]); lookback=metadata["lookback"]
            if len(states)<lookback: raise ValueError(f"At least {lookback} time windows are needed.")
            model,scaler,_=load_lstm(ARTIFACTS); latest=states[FEATURE_COLUMNS].to_numpy(dtype=np.float32)[-lookback:]
            scaled=scaler.transform(latest).reshape(1,lookback,-1)
            with torch.no_grad(): score=float(torch.sigmoid(model(torch.tensor(scaled,dtype=torch.float32)))[0])
            st.metric("Uploaded CSV progression estimate",f"{score:.1%}")
            current=states.iloc[-1][FEATURE_COLUMNS].to_dict()
            for item in map_attack_stage(score,current): st.write(f"**{item['stage']}** — {item['technique']}: {item['reason']}")
        except Exception as exc:
            st.error(f"Could not forecast this file: {exc}")
