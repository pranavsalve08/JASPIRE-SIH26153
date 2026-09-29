import numpy as np
import pandas as pd

def generate_demo_flows(windows: int = 360, seed: int = 7) -> pd.DataFrame:
    rng=np.random.default_rng(seed); start=pd.Timestamp("2026-01-01T09:00:00Z"); rows=[]
    attack_windows=set(range(125,145)) | set(range(245,275)) | set(range(330,350))
    for window in range(windows):
        attack=window in attack_windows
        count=int(rng.integers(35,55) if attack else rng.integers(9,16))
        for _ in range(count):
            rows.append({"timestamp":start+pd.Timedelta(seconds=window*60+int(rng.integers(60))),
                "src_ip":f"10.0.{9 if attack else 1}.{rng.integers(1,15 if attack else 7)}",
                "dst_ip":f"10.0.2.{rng.integers(1,14)}", "src_port":int(rng.integers(1024,65535)),
                "dst_port":int(rng.integers(1,2000) if attack else rng.choice([53,80,443])),
                "protocol":"tcp" if rng.random()>.2 else "udp", "duration":float(rng.exponential(.2)),
                "packets":int(rng.integers(1,8)), "bytes":int(rng.integers(100,12000) if attack else rng.integers(100,2500)),
                "label":"port_scan" if attack else "benign"})
    return pd.DataFrame(rows)
