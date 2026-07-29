================================================================================
IDPS PROJECT ANALYSIS REPORT
================================================================================
Timestamp     : 2026-06-02 00:00:00 UTC
Analyst       : IDPS Project Analyst Agent
Scope         : Attack Graph & Incident Investigation System — Pre-Redesign Audit
Project Phase : Feature Redesign (Attack Graph v2)
================================================================================

## EXECUTIVE SUMMARY

The current `attack_graph.py` is a structurally sound event-to-graph translator
but is missing every feature listed in the redesign spec: no `threat_actor`/
`technique` node types, no `_MITRE_MAP`, no `_INBOUND_ATTACKS` edge-direction
fix, no `ingest_to_incident()` correlation engine, and no `/incidents`
endpoints. The frontend `types.ts` and `GraphControls.tsx` are equally
unprepared — `NodeType` does not include `threat_actor` or `technique`, and
`GraphControls` has no speed selector. The redesign is correct in direction and
the existing scaffolding is clean enough to build on. Overall health: **4/10**
against the stated redesign target.

---

## SECTION 1: ARCHITECTURE ASSESSMENT

### Five Scenario Coverage

| Scenario | Current state | Gap |
|---|---|---|
| Port Scan | `process_network_anomaly` creates endpoint + ip nodes, edge `connected_to` | No `threat_actor` node; edge direction is `endpoint -> ip` (wrong for inbound scan) |
| Brute Force | Same network path; no dedicated processor | No `threat_actor`; source IP treated as destination detail, not attacker origin |
| Malware | `process_malware_alert` creates process node with label/hash/SHAP | Correct direction; no MITRE technique node linked |
| Ransomware | Falls through to `process_fusion_alert` if fusion engine labels it | No scenario-specific correlation; no technique node |
| Insider Threat | `process_user_anomaly` creates user node, edge `authenticated_as endpoint` | Direction is correct; no lateral-movement chaining across multiple endpoints |

All five scenarios require the `threat_actor` node type and the `_INBOUND_ATTACKS`
direction fix before they model real attack topology.

---

## SECTION 2: EDGE DIRECTION CORRECTNESS

The current `process_network_anomaly` always draws `endpoint_<id> -> ip_<dst>`.
For outbound C2 beaconing this is correct. For inbound attacks (PortScan, DDoS,
BruteForce) the attacker IP is `src_ip`, not `dst_ip`, so the edge must be
`threat_actor_<src_ip> -> endpoint_<id>`.

The proposed `_INBOUND_ATTACKS` set should include at minimum:

```
{"PortScan", "DDoS", "BruteForce", "Heartbleed", "Infiltration",
 "SYN_FLOOD", "HOST_SWEEP", "PORT_SCAN_HORIZONTAL"}
```

The last three names are the string literals returned by `rule_detector.py` and
must match exactly — the redesign spec does not list them.

---

## SECTION 3: MITRE COVERAGE GAP

Attack type strings produced by the existing codebase that the redesign's
`_MITRE_MAP` must cover:

| Attack type string | Source | MITRE if mapped |
|---|---|---|
| `BENIGN` | RandomForest classifier | — (no technique needed) |
| `Botnet` | RandomForest | T1071 |
| `BruteForce` | RandomForest + rule | T1110 |
| `DDoS` | RandomForest + rule | T1498 |
| `DoS` | RandomForest | T1499 |
| `Heartbleed` | RandomForest | T1499 |
| `Infiltration` | RandomForest | T1190 |
| `PortScan` | RandomForest + rule | T1046 |
| `PORT_SCAN_HORIZONTAL` | rule_detector | T1046 |
| `HOST_SWEEP` | rule_detector | T1046 |
| `SYN_FLOOD` | rule_detector | T1498 |
| `C2 Beaconing` | hybrid_detector label | T1071 |
| `Ransomware Activity` | fusion_engine | T1486 |
| `Ransomware Behavior` | fusion_engine (legacy) | T1486 |
| `Malware Activity` | `_maybe_emit_malware_fusion_alert` | T1204 |
| `Insider Threat` | user_behavior_agent | T1078 |
| `Privilege Escalation` | response_engine literal | T1068 |
| `Lateral Movement` | response_engine literal | T1021 |
| `Network Anomaly` | generic fallback | T1059 |
| `Fusion Alert` | generic fallback | T1059 |

Entries most likely to be missed: `PORT_SCAN_HORIZONTAL`, `HOST_SWEEP`,
`SYN_FLOOD` (rule_detector names use underscores, not spaces), and
`Ransomware Behavior` (legacy fusion label still present in some code paths).

---

## SECTION 4: CORRELATION WINDOW

A 30-minute window is reasonable for most multi-stage campaigns (initial
recon -> exploitation -> lateral movement typically spans 15–45 minutes in
observed TTPs). Trade-offs:

- **Too short (<10 min)**: Slow APT campaigns split across reboots will create
  separate incidents; BruteForce followed by delayed lateral movement (T1021)
  will not correlate.
- **Too long (>60 min)**: Unrelated, coincident events from different source
  IPs will merge into a single inflated incident, degrading specificity.
- **30 min is appropriate** provided the grouping key also partitions by
  `endpoint_id` or `src_ip`; if incidents are grouped only by time window
  without a secondary key, a scan against endpoint A and an unrelated malware
  hit on endpoint B will falsely merge.

**Recommendation**: Group by `(time_bucket_30min, endpoint_id)` as co-equal
keys. Optionally add `src_ip` as a third key for inbound attacks.

---

## SECTION 5: ONE REAL GAP FOUND DURING CODE INSPECTION

**`mark_endpoint_offline` uses wrong node ID prefix.**

At line 310, the method constructs the node lookup key as `f"ep-{endpoint_id}"`.
Every other method in the same file uses `f"endpoint_{endpoint_id}"` as the
node ID convention (lines 134, 163, 192, 221, 239, 293). The `$update_one`
query will never match any node, silently failing to mark endpoints offline.
This is a live bug independent of the redesign and should be patched in the
current file before the redesign branch is started.

**Fix**: Change line 310 to `nid = f"endpoint_{endpoint_id}"`.

---

## SECTION 6: FRONTEND GAPS

Both `types.ts` and `GraphControls.tsx` require updates before the redesign
backend can be consumed:

| File | Missing |
|---|---|
| `types.ts` line 5 | `NodeType` union must add `"threat_actor" \| "technique"` |
| `types.ts` line 108 | `NODE_STYLE` must add entries for `threat_actor` and `technique` |
| `types.ts` lines 141–149 | `BackendEdge` interface missing `mitre_technique`, `attack_type`, `confidence`, `correlation_score` fields the redesign adds |
| `GraphControls.tsx` line 87 | `GraphControlsProps` has no `replaySpeed` or `setReplaySpeed` — speed selector described in spec is absent |
| `GraphControls.tsx` | `LEGEND_NODES` array hardcoded; `threat_actor` / `technique` not listed |

---

## VERDICT

**AMBER**

The redesign plan is architecturally correct and addresses real deficiencies in
the current graph model. The existing code is clean and extensible. However,
none of the specified changes exist yet in `attack_graph.py`, `types.ts`, or
`GraphControls.tsx` — the report is assessing a pre-implementation state.
One pre-existing bug (`mark_endpoint_offline` node ID mismatch) must be patched
regardless of the redesign. MITRE map must explicitly include rule_detector
underscore-named attack types to avoid silent coverage gaps. The implementation
is ready to proceed at AMBER confidence.

================================================================================
END OF REPORT
Next Analysis Recommended: After redesign implementation is merged — verify
  `ingest_to_incident()` grouping keys, `_INBOUND_ATTACKS` string coverage,
  and frontend NodeType union exhaustiveness.
================================================================================
