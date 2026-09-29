from __future__ import annotations

import numpy as np
import pandas as pd

FEATURE_COLUMNS = ["flow_count", "unique_sources", "unique_destinations", "unique_dst_ports",
                   "total_bytes", "total_packets", "mean_duration", "tcp_ratio", "udp_ratio",
                   "high_port_ratio", "new_source_ratio"]

def build_network_states(flows: pd.DataFrame, window_seconds: int = 60) -> pd.DataFrame:
    data = flows.copy().sort_values("timestamp")
    data["window"] = data["timestamp"].dt.floor(f"{window_seconds}s")
    data["is_tcp"] = (data["protocol"] == "tcp").astype(int)
    data["is_udp"] = (data["protocol"] == "udp").astype(int)
    data["is_high_port"] = (data["dst_port"] >= 1024).astype(int)
    first_seen = data.groupby("src_ip")["timestamp"].transform("min")
    data["is_new_source"] = (data["timestamp"] == first_seen).astype(int)
    rows = []
    for when, group in data.groupby("window", sort=True):
        count = len(group)
        rows.append({"window": when, "flow_count": count,
            "unique_sources": group.src_ip.nunique(), "unique_destinations": group.dst_ip.nunique(),
            "unique_dst_ports": group.dst_port.nunique(), "total_bytes": group.bytes.sum(),
            "total_packets": group.packets.sum(), "mean_duration": group.duration.mean(),
            "attack_flow_ratio": group.is_attack.mean(), "tcp_ratio": group.is_tcp.mean(),
            "udp_ratio": group.is_udp.mean(), "high_port_ratio": group.is_high_port.mean(),
            "new_source_ratio": group.is_new_source.sum() / count})
    return pd.DataFrame(rows).fillna(0)

def make_sequences(states: pd.DataFrame, lookback: int = 8, horizon: int = 1):
    """Build history sequences; predict whether a future window has attack labels."""
    values = states[FEATURE_COLUMNS].to_numpy(dtype=np.float32)
    future_attack = (states.attack_flow_ratio.to_numpy() > 0).astype(np.int64)
    xs, ys = [], []
    for end in range(lookback, len(states) - horizon + 1):
        xs.append(values[end - lookback:end])
        ys.append(int(future_attack[end:end + horizon].any()))
    if not xs:
        raise ValueError("Not enough time windows for sequences; reduce lookback or add data.")
    return np.stack(xs), np.asarray(ys)
