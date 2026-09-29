def map_attack_stage(probability: float, state: dict) -> list[dict]:
    """Provide transparent ATT&CK-oriented review hypotheses, not attribution."""
    if probability < 0.35:
        return [{"stage": "No elevated progression signal", "technique": "—", "reason": "Forecast below review threshold."}]
    items = []
    if state.get("unique_dst_ports", 0) >= 8:
        items.append({"stage": "Discovery", "technique": "T1046 Network Service Discovery", "reason": "Many destination ports appeared in this network window."})
    if state.get("unique_sources", 0) >= 5 or state.get("new_source_ratio", 0) > .25:
        items.append({"stage": "Initial Access review", "technique": "T1190 Exploit Public-Facing Application", "reason": "New or numerous sources warrant analyst review."})
    if state.get("total_bytes", 0) > 5_000_000:
        items.append({"stage": "Possible command and control / exfiltration", "technique": "T1041 Exfiltration Over C2 Channel", "reason": "Unusually high byte volume needs corroboration."})
    if not items:
        items.append({"stage": "Analyst review", "technique": "No technique attributed", "reason": "Network-only features cannot confirm a technique."})
    return items
