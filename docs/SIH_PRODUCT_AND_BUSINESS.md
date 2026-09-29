# JASPIRE: SIH feasibility, deployment, and business plan

**Problem:** SIH26153  
**Product:** JASPIRE, an analyst-facing network attack progression forecast prototype

## Feasibility and viability

The offline MVP is technically feasible as a demo: flow CSV/optional PCAP ingestion, fixed time-window states, LSTM and Logistic Regression baseline, feature importance, ATT&CK-oriented hypotheses, and local Streamlit UI. Forecast validity is not established. The synthetic demonstration is reproducible but its scores are not real-world evidence.

Operational viability is conditional on representative labelled flows, accurate timestamps, integration with existing telemetry, privacy controls, and analyst review. Commercial viability is plausible but unproven. The value hypothesis is reduced triage effort and better prioritisation; customer pilots must establish lift and willingness to pay.

The next validation step is a shadow-mode pilot: score one approved network segment without changing response actions. Compare against analyst dispositions and a simple baseline. Measure precision-recall, false alerts per day, lead time, calibration, and analyst time saved on a later time period.

## Deployment path

**Hackathon or small pilot:** run locally on an analyst workstation; start with generated data, then use an approved minimised flow export. Keep raw PCAP and customer data outside GitHub. Limit the pilot to one segment, a fixed observation period, and documented success measures.

**Production direction:** customer-controlled collectors (Zeek, NetFlow/IPFIX, firewall exports) feed a private processing service; validate schemas and timestamps; aggregate windows; score with versioned models; monitor drift and failures; send evidence to the existing SIEM/SOAR case queue. Require human validation. Add role-based access, encryption, audit logs, retention/deletion controls, tenant separation, incident response, and time-based model evaluation.

On-premises/private cloud may suit data-sensitive deployments; an approved managed cloud is another option. The current MVP implements only the local/offline path. Streaming connectors, SIEM/SOAR integration, multi-tenant hosting, and production controls are roadmap items, not current capabilities.

## Indicative cost structure

Planning ranges in INR, not vendor quotes. Rough India-based estimates; exclude GST, team opportunity cost for the demo, and customer procurement. Actual spend depends on staffing, data volume, assurance, and integrations.

| Stage | Indicative budget | Main drivers |
| --- | ---: | --- |
| Hackathon/lab demo | ₹0–₹25,000 cash | Existing laptop, open-source stack, optional hosting/presentation expenses |
| Proof of value, 6–10 weeks | ₹3–₹12 lakh | 2–3 staff, integration, secure environment, evaluation |
| Early production, annual | ₹35 lakh–₹1.2 crore | 3–6 person team, compute/storage, monitoring, support, security review |
| Larger enterprise, annual | ₹1.2–₹4 crore+ | High availability, multiple connectors, operations, assurance, larger data scale |

Recurring costs include people, secure transport, compute/storage, observability, model/data evaluation, support, security assurance, and connector maintenance. Retain flow summaries where possible; raw PCAP retention increases storage and privacy costs.

## Business model and ecosystem

Initial buyers to validate: organisations with SOC analysts, existing network flow telemetry, and a costly alert triage burden; potential segments include mid-market enterprises, MSSPs, and regulated organisations.

Candidate revenue streams:
- Fixed-scope paid proof-of-value engagements with agreed success criteria.
- Annual software subscription priced by monitored assets, traffic tier, or deployment size.
- Customer-managed/on-premises licence plus annual support and model updates.
- Scoped onboarding, integration, and custom connector services.
- OEM or managed-service partnerships with an MSSP or security vendor.

Pricing and willingness to pay are unvalidated. Pilot conversion should depend on demonstrated analyst-time savings and workflow benefit versus subscription and integration cost.

The ecosystem can include flow exporters (Zeek/NetFlow/IPFIX), existing SIEM/SOAR and case tools, MITRE ATT&CK as investigation vocabulary, customer infrastructure/private-cloud providers, SOC analysts, privacy/security reviewers, and pilot partners such as MSSPs or system integrators.

## Consistent SIH presentation

> JASPIRE turns time-ordered network-flow behaviour into an analyst-reviewed estimate of attack progression risk for the next time window.

Keep these claims aligned across slides and demo:
- Name/problem: JASPIRE, SIH26153, network attack progression forecasting.
- Data path: PCAP/CSV flow export → normalisation → time windows → temporal forecast → evidence and risk → ATT&CK hypotheses → analyst review.
- State clearly that demo data and scores are synthetic; show time-held-out LSTM and baseline metrics only with dataset and label context.
- Forecasts support human prioritisation; no automatic blocking, attribution, or response.
- Label cost ranges and revenue packaging as planning assumptions, not market validation.
- Describe future connectors, SaaS, and production controls as roadmap until implemented.

Suggested slide order: problem/user → value → architecture → prototype walkthrough → evaluation → feasibility and deployment → cost/business model → risks and pilot milestone. Do not show private customer addresses, raw packet captures, or unverified benchmark claims.
