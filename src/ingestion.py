from __future__ import annotations
from pathlib import Path
import pandas as pd

ALIASES = {
    "timestamp": ["timestamp", "time", "flow start", "flow start time", "ts"],
    "src_ip": ["src ip", "source ip", "sourceip", "id.orig h", "source"],
    "dst_ip": ["dst ip", "destination ip", "destinationip", "id.resp h", "destination"],
    "src_port": ["src port", "source port", "sourceport", "id.orig p"],
    "dst_port": ["dst port", "destination port", "destinationport", "id.resp p"],
    "protocol": ["protocol", "proto"], "duration": ["flow duration", "duration", "duration seconds"],
    "packets": ["total fwd packets", "tot pkts", "packets", "orig pkts"],
    "bytes": ["total length of fwd packets", "totlen fwd pkts", "bytes", "orig bytes"],
    "label": ["label", "attack", "class", "event type"],
}

def _clean(name):
    return " ".join(str(name).strip().lower().replace("_", "  ").replace("-", "  ").split())

def normalise_flows(raw: pd.DataFrame) -> pd.DataFrame:
    lookup = {_clean(c): c for c in raw.columns}
    found = {}
    for target, names in ALIASES.items():
        source = next((lookup[n] for n in names if n in lookup), None)
        if source is not None: found[target] = raw[source]
    missing = {"timestamp", "src_ip", "dst_ip"} - set(found)
    if missing: raise ValueError(f"CSV is missing required fields: {', '.join(sorted(missing))}")
    data = pd.DataFrame(found)
    data["timestamp"] = pd.to_datetime(data.timestamp, errors="coerce", utc=True)
    data = data.dropna(subset=["timestamp", "src_ip", "dst_ip"]).copy()
    for col in ("src_port", "dst_port", "duration", "packets", "bytes"):
        if col not in data: data[col] = 0
        data[col] = pd.to_numeric(data[col], errors="coerce").fillna(0)
    if "protocol" not in data: data["protocol"] = "unknown"
    data["protocol"] = data.protocol.fillna("unknown").astype(str).str.lower()
    labels = data.get("label", pd.Series("", index=data.index)).fillna("").astype(str).str.lower().str.strip()
    data["is_attack"] = (~labels.isin(["", "0", "benign", "normal", "false", "background"])).astype(int)
    return data.sort_values("timestamp").reset_index(drop=True)

def read_csv(path: str | Path) -> pd.DataFrame:
    return normalise_flows(pd.read_csv(path, low_memory=False))

def read_pcap(path: str | Path) -> pd.DataFrame:
    try:
        from scapy.all import IP, TCP, UDP, PcapReader
    except ImportError as exc:
        raise RuntimeError("PCAP input requires Scapy: pip install scapy") from exc
    flows = {}
    with PcapReader(str(path)) as packets:
        for packet in packets:
            if IP not in packet: continue
            ip = packet[IP]; transport = packet[TCP] if TCP in packet else packet[UDP] if UDP in packet else None
            sport = int(transport.sport) if transport else 0; dport = int(transport.dport) if transport else 0
            proto = "tcp" if TCP in packet else "udp" if UDP in packet else str(ip.proto)
            key = (ip.src, ip.dst, sport, dport, proto); stamp = pd.Timestamp(float(packet.time), unit="s", tz="UTC")
            row = flows.setdefault(key, {"timestamp": stamp, "src_ip": ip.src, "dst_ip": ip.dst, "src_port": sport, "dst_port": dport, "protocol": proto, "duration": 0., "packets": 0, "bytes": 0, "label": ""})
            row["duration"] = max(row["duration"], (stamp-row["timestamp"]).total_seconds()); row["packets"] += 1; row["bytes"] += len(packet)
    if not flows: raise ValueError("No IPv4 packets found in the PCAP.")
    return normalise_flows(pd.DataFrame(flows.values()))
