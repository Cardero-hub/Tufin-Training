# Tufin SecureTrack API Validation Log
## Harrington & Voss — Pre-Sales PoC

---

## Call 1 — Retrieve All Managed Devices (Paginated, First 10)

### Full URL
```
https://1192.168.1.1/securetrack/api/devices?start=0&count=10
```


### HTTP Method
```
GET
```

### Expected HTTP Status on Success
```
200 OK
```

### Response DTO — Expected Structure
```json
{
  "devices": {
    "count": 10,
    "total": 12,
    "device": [
      {
        "id": 1,
        "name": "FW-TRADING-01",
        "vendor": "Fortinet",
        "model": "FortiGate-600E",
        "domain_id": 1,
        "domain_name": "Default",
        "ip": "10.10.0.1",
        "latest_revision": 47,
        "virtual_type": "base_device",
        "device_type": "Firewall",
        "status": "Connected",
        "parent_id": null
      },
      {
        "id": 2,
        "name": "CP-DC-GW-01",
        "vendor": "Check Point",
        "model": "R80.40",
        "domain_id": 1,
        "domain_name": "Default",
        "ip": "10.50.0.1",
        "latest_revision": 31,
        "virtual_type": "base_device",
        "device_type": "Firewall",
        "status": "Connected",
        "parent_id": null
      }
      // ... additional devices
    ]
  }
}
```

**Key DTO fields:**
- `id` — internal SecureTrack device ID (used in all subsequent calls)
- `vendor` — confirms multi-vendor coverage (Fortinet + Check Point)
- `model` — identifies specific appliance/platform version
- `status` — `Connected` = live sync healthy; anything else = visibility gap
- `latest_revision` — shows how many policy revisions SecureTrack has ingested
- `virtual_type` — distinguishes physical devices from virtual domains / VSX contexts

### Pre-Sales Engineer Notes — What This Tells Us About Harrington & Voss

**What to expect:** In a healthy onboarding, this response should surface at minimum two parent devices — a Fortinet FortiGate entry (`vendor: "Fortinet"`) and a Check Point management object (`vendor: "Check Point"`), reflecting the dual-vendor architecture described in the environment questionnaire. Additional entries may represent the Check Point SmartCenter management server as a separate object from its enforcing gateway, which is normal for R80.x deployments.

**What would concern us if Fortinet devices are missing:** Absence of any Fortinet entry signals a connectivity or credential failure between SecureTrack and the FortiManager/FortiGate API. For a financial institution like Harrington & Voss whose trading VLAN segmentation (`vlan-trading 10.20.1.0/24`) lives entirely behind the Fortinet perimeter, a missing device means zero policy visibility for that segment. Every subsequent topology query and compliance check for the trading side would be blind. This must be resolved before any PoC objective can be demonstrated.

**What would concern us if Check Point devices are missing:** Check Point absence would leave the data centre feeds network (`10.50.2.0/24`) and the associated market data zone unmonitored. For PoC Objective 3 (PCI DSS compliance), Check Point hosts the cardholder data environment gateway — without it SecureTrack cannot assess whether CDE-adjacent rules comply with PCI DSS Requirement 1. A missing Check Point entry also typically indicates that the SmartCenter API credentials provided during onboarding (`api key` or password-based auth) were not accepted, or that the Management API is not enabled on the SmartCenter server.

**Revision count as a health indicator:** A `latest_revision` count above 1 confirms that SecureTrack has successfully completed at least one policy pull cycle. A device showing `revision: 0` or `status: "Disconnected"` is a red flag requiring immediate attention before the PoC demonstration.

---

## Call 2 — Retrieve Firewall Rules for Fortinet Device (Device ID 1, Rules 1–8)

### Full URL
```
https://192.168.1.1/securetrack/api/devices/1/rules?start=0&count=8
```


### HTTP Method
```
GET
```

### Expected HTTP Status on Success
```
200 OK
```

### Response DTO — Expected Structure
```json
{
  "rules": {
    "count": 8,
    "total": 8,
    "rule": [
      {
        "id": 101,
        "number": 1,
        "name": "ALLOW-TRADING-TO-MARKET-DATA",
        "status": "enabled",
        "action": "Accept",
        "comment": "Trading desk to Bloomberg/Reuters feeds",
        "src": {
          "network_object": [
            { "name": "vlan-trading", "ip": "10.20.1.0", "netmask": "255.255.255.0" }
          ]
        },
        "dst": {
          "network_object": [
            { "name": "mkt-data-feeds", "ip": "10.50.2.0", "netmask": "255.255.255.0" }
          ]
        },
        "service": {
          "service_object": [
            { "name": "HTTPS", "port": 443, "protocol": "TCP" },
            { "name": "Bloomberg-API", "port": 8194, "protocol": "TCP" }
          ]
        },
        "track": "Log",
        "last_modified": "2024-11-14T09:22:00Z",
        "is_disabled": false,
        "shadowed_by": null,
        "certification_status": "NOT_CERTIFIED",
        "usage": {
          "hit_count": 148432,
          "last_hit": "2025-06-02T23:58:00Z"
        }
      },
      {
        "id": 108,
        "number": 8,
        "name": "DENY-ALL",
        "status": "enabled",
        "action": "Drop",
        "comment": "Implicit deny — explicit log",
        "src": { "network_object": [{ "name": "Any" }] },
        "dst": { "network_object": [{ "name": "Any" }] },
        "service": { "service_object": [{ "name": "Any" }] },
        "track": "Log",
        "last_modified": "2024-09-01T00:00:00Z",
        "is_disabled": false
      }
    ]
  }
}
```

**Key DTO fields:**
- `number` — rule sequence number in the policy (order matters for rule shadowing analysis)
- `action` — `Accept`, `Drop`, or `Deny`
- `src` / `dst` — resolved network objects including named groups and CIDRs
- `service` — named service objects and custom port/protocol definitions
- `track` — logging state; `None` = stealth rule with no audit trail
- `certification_status` — `NOT_CERTIFIED` flags rules that need owner review
- `usage.hit_count` / `usage.last_hit` — rule utilisation data for cleanup analysis
- `shadowed_by` — if populated, identifies the rule that makes this rule unreachable

### Pre-Sales Engineer Notes — Discovery Insights for Harrington & Voss

**The specific discovery insight to look for:** The response will expose the `service` objects attached to each rule in machine-readable form. During the Fortinet onboarding walkthrough, the team noted a rule permitting trading VLAN access to market data feeds on port 443. However, if the DTO shows that the same rule also permits port `8194` (Bloomberg B-PIPE) or port `6970–6971` (Reuters/TREP), this reveals that custom financial-services ports are being allowed under a broadly named service object — possibly even `Any` services with `action: Accept`. This is a classic **over-permissive rule pattern** common in trading environments where rules were broadened under time pressure during onboarding of new data vendor connections and never tightened.

**What makes this Harrington & Voss-specific:** A rule numbered 1 with `action: Accept`, `src: Any`, and `dst: mkt-data-feeds` with `track: None` (no logging) would be an immediate red flag. It suggests an engineer added a "quick fix" permit rule at the top of the policy to unblock a Bloomberg outage and never revisited it. SecureTrack surfaces this because the DTO preserves both `rule_number` (order) and `certification_status` — a combination that makes the risk visible at a glance, not buried in a 300-rule policy export.

**Cleanup signal:** Any rule where `usage.last_hit` is more than 90 days ago and `usage.hit_count` is zero warrants a recertification conversation with the Fortinet admin. For a trading desk, a zero-hit rule on the egress path to market data feeds could indicate a dead route or a redundant rule protecting a decommissioned feed connection — exactly the kind of policy debt Tufin's Rule Lifecycle Management is designed to surface.

---

## Call 3 — Retrieve Firewall Rules for Check Point Device (Device ID 2, Rules 1–9)

### Full URL
```
https://192.168.1.1/securetrack/api/devices/2/rules?start=0&count=9
```

### HTTP Method
```
GET
```

### Expected HTTP Status on Success
```
200 OK
```

### Response DTO — Expected Structure
```json
{
  "rules": {
    "count": 9,
    "total": 9,
    "rule": [
      {
        "id": 201,
        "uid": "{A4C7E2B1-3D9F-4A02-BF71-9C3E1D48F72A}",
        "number": 1,
        "name": "STEALTH-RULE",
        "status": "enabled",
        "action": "Drop",
        "comment": "Protect the gateway — do not delete",
        "src": { "network_object": [{ "name": "Any" }] },
        "dst": {
          "network_object": [
            { "name": "CP-DC-GW-01", "type": "gateway" }
          ]
        },
        "service": { "service_object": [{ "name": "Any" }] },
        "track": "Log",
        "layer": "Network",
        "inline_layer": null,
        "certification_status": "CERTIFIED",
        "usage": {
          "hit_count": 3102,
          "last_hit": "2025-06-03T00:01:00Z"
        }
      },
      {
        "id": 209,
        "uid": "{FF00A3C1-0000-0000-0000-CLEANUP0001}",
        "number": 9,
        "name": "CLEANUP-RULE",
        "status": "enabled",
        "action": "Drop",
        "comment": "Log and drop everything else",
        "src": { "network_object": [{ "name": "Any" }] },
        "dst": { "network_object": [{ "name": "Any" }] },
        "service": { "service_object": [{ "name": "Any" }] },
        "track": "Log",
        "layer": "Network"
      }
    ]
  }
}
```

**Additional Check Point-specific DTO fields:**
- `uid` — Check Point object GUIDs (globally unique; persist across policy revisions)
- `layer` — identifies whether the rule lives in the base `Network` layer or an `Inline` sub-policy layer (Check Point R80+ layered policy feature)
- `inline_layer` — if populated, references a named sub-policy object; rules here must be retrieved with a separate layer-scoped API call

### Pre-Sales Engineer Notes — Interpreting Check Point vs Fortinet Rule Data

**Structural difference — layered policies:** The single most important interpretive difference for a Pre-Sales Engineer is Check Point's **R80.x layered policy model**. When the response contains rules with `inline_layer` populated, it means the rule at that position does not contain final access logic itself — it is a *pointer* to a sub-policy layer where the real permit/deny decisions live. A Fortinet response is flat: every rule you see is an enforceable decision. A Check Point response may be a two-level tree where the top-level rule says `Accept` but the inline layer beneath it contains the granular controls.

**Practical implication:** If Harrington & Voss's Check Point admin has created a "Data Centre Access" top-level rule with `action: Accept` and then scoped the real controls inside an inline layer named `"DC-Granular-Policy"`, a Pre-Sales Engineer reviewing only the top-level rule list would see an apparently permissive `Accept` rule and flag it as a risk — when in fact the inline layer is correctly restrictive. SecureTrack handles this correctly by resolving the full layered hierarchy, but it is important to call this out to the client so they understand *why* SecureTrack's compliance view may look different from a manual policy review.

**UID vs rule number:** Fortinet rules are referenced by sequential `number` (position-dependent). Check Point rules carry a `uid` GUID that is **position-independent** — it stays the same even if the rule is renumbered after a policy reorder. For Harrington & Voss, this matters for change tracking: SecureTrack's change reports will reference Check Point rules by UID, which means cross-referencing against a SecureChange ticket or a manual change log requires the admin to map UIDs to names. This is a workflow conversation point — automation via SecureChange would eliminate that manual step.

**Stealth rule as a compliance signal:** Check Point best practice mandates a stealth rule (drop all traffic to the gateway itself) as rule #1. If the DTO response shows rule #1 as anything other than `action: Drop` targeting the gateway object, this is a PCI DSS Requirement 1.3 finding: the firewall management interface is potentially reachable from the network. For Harrington & Voss, whose Check Point gateway sits in the data centre segment alongside trading infrastructure, this would be a critical finding to present to Tobias Richter.

---

## Call 4 — Topology Path Query: Fortinet vlan-trading → Check Point DC Trading Feeds

### Full URL
```
https://192.168.1.1/securetrack/api/topology/path?src=10.20.1.0/24&dst=10.50.2.0/24&service=tcp:443
```


### HTTP Method
```
GET
```

### Expected HTTP Status on Success
```
200 OK
```

### Response DTO — Expected Structure

**Scenario A — Path permitted end-to-end:**
```json
{
  "path_calc_results": {
    "result": "Permitted",
    "hops": [
      {
        "hop_type": "Firewall",
        "device_id": 1,
        "device_name": "FW-TRADING-01",
        "vendor": "Fortinet",
        "ingress_interface": "vlan-trading",
        "egress_interface": "wan-dc-link",
        "matched_rule": {
          "rule_id": 101,
          "rule_number": 1,
          "rule_name": "ALLOW-TRADING-TO-MARKET-DATA",
          "action": "Accept"
        }
      },
      {
        "hop_type": "Firewall",
        "device_id": 2,
        "device_name": "CP-DC-GW-01",
        "vendor": "Check Point",
        "ingress_interface": "eth0-dc-ingress",
        "egress_interface": "eth1-mktdata",
        "matched_rule": {
          "rule_uid": "{A4C7E2B1-FEED-0001-0000-DC0001000001}",
          "rule_number": 3,
          "rule_name": "ALLOW-INTERNAL-MKTDATA",
          "action": "Accept"
        }
      }
    ],
    "traffic_allowed": true,
    "nat_applied": false
  }
}
```

**Scenario B — Path blocked or no route:**
```json
{
  "path_calc_results": {
    "result": "Blocked",
    "hops": [
      {
        "hop_type": "Firewall",
        "device_id": 1,
        "device_name": "FW-TRADING-01",
        "vendor": "Fortinet",
        "ingress_interface": "vlan-trading",
        "egress_interface": null,
        "matched_rule": {
          "rule_id": 108,
          "rule_number": 8,
          "rule_name": "DENY-ALL",
          "action": "Drop"
        }
      }
    ],
    "traffic_allowed": false,
    "block_reason": "Dropped at FW-TRADING-01 rule #8 (implicit deny)"
  }
}
```

### Pre-Sales Engineer Notes — Why This Path Matters for Harrington & Voss

**Business criticality:** The path from `10.20.1.0/24` (Fortinet-managed trading VLAN) to `10.50.2.0/24` (Check Point-guarded data centre trading feeds network) is the **critical revenue path** for Harrington & Voss's trading operations. Market data feeds from Bloomberg and Reuters flow inbound from `10.50.2.0/24` to the trading desks in `10.20.1.0/24`. Any interruption, unintended block, or mis-applied firewall rule on this path directly translates to trading latency, missed price updates, or a complete inability to execute orders during market hours.

**Why this specific query is a PoC proof-point:** This path traverses *two different vendor firewalls* — the Fortinet gateway at the trading perimeter and the Check Point gateway at the data centre boundary. Without Tufin, a network engineer diagnosing a connectivity issue on this path would need to log into two separate management consoles (FortiManager for Fortinet, SmartConsole for Check Point), manually trace the routing table to identify which interfaces the traffic traverses, then cross-reference two separate rule bases. SecureTrack's topology engine performs this correlation automatically and presents the end-to-end verdict in a single API response.

**What the response reveals:**
- **If `result: "Permitted"`** — confirms that the two firewalls are correctly configured to allow trading feed traffic and that SecureTrack has successfully correlated the routing topology across both vendors. This is the expected state and should be demonstrated live in the PoC.
- **If `result: "Blocked"`** — the `matched_rule` in the blocking hop immediately identifies the offending rule by number and name, giving the network team actionable information without a manual policy audit.
- **If `result: "No Path"`** — SecureTrack has not yet learned the routing topology between the two devices (e.g., the inter-device routing is via an unmonitored switch/router). This is a discovery finding: Harrington & Voss has a topology gap that blind-spots the most critical traffic path in their environment.
- **NAT detection:** If `nat_applied: true`, the response will include pre-NAT and post-NAT addresses, revealing whether the trading VLAN traffic is being source-NATted before hitting the Check Point policy — a configuration detail that is easy to miss and can cause compliance misattribution.

---

## Call 5 — PCI DSS Compliance Report for All Devices

### Full URL
```
https://192.168.1.1/securetrack/api/violating_rules?policy=PCI_DSS&start=0&count=100
```


### HTTP Method
```
GET
```

### Expected HTTP Status on Success
```
200 OK
```

### Response DTO — Expected Structure
```json
{
  "violating_rules": {
    "count": 14,
    "total": 14,
    "violating_rule": [
      {
        "device_id": 1,
        "device_name": "FW-TRADING-01",
        "vendor": "Fortinet",
        "rule_id": 103,
        "rule_number": 3,
        "rule_name": "LEGACY-MGMT-ACCESS",
        "violation": {
          "policy": "PCI_DSS",
          "requirement": "Requirement 1.3.2",
          "severity": "CRITICAL",
          "description": "Rule permits inbound traffic from untrusted zone to cardholder data environment without restriction by IP",
          "usp_zone_src": "External",
          "usp_zone_dst": "CDE",
          "traffic_allowed": true
        },
        "action": "Accept",
        "src": { "network_object": [{ "name": "Any" }] },
        "dst": { "network_object": [{ "name": "cde-hosts" }] },
        "service": { "service_object": [{ "name": "Any" }] }
      },
      {
        "device_id": 2,
        "device_name": "CP-DC-GW-01",
        "vendor": "Check Point",
        "rule_id": 205,
        "rule_number": 5,
        "rule_name": "OLD-ADMIN-RULE",
        "violation": {
          "policy": "PCI_DSS",
          "requirement": "Requirement 7.1",
          "severity": "HIGH",
          "description": "Rule grants broad administrative access to in-scope systems beyond principle of least privilege",
          "usp_zone_src": "Management",
          "usp_zone_dst": "CDE",
          "traffic_allowed": true
        },
        "action": "Accept",
        "src": { "network_object": [{ "name": "mgmt-net", "ip": "10.99.0.0", "netmask": "255.255.0.0" }] },
        "dst": { "network_object": [{ "name": "Any" }] },
        "service": { "service_object": [{ "name": "Any" }] }
      }
    ]
  }
}
```

**Key DTO fields:**
- `violation.policy` — confirms which USP/compliance framework triggered the violation
- `violation.requirement` — maps the violation to a specific PCI DSS requirement number (auditor-ready)
- `violation.severity` — `CRITICAL`, `HIGH`, `MEDIUM`, `LOW` — prioritises remediation queue
- `violation.usp_zone_src` / `usp_zone_dst` — maps source/destination to named security zones (e.g., `External`, `CDE`, `Management`)
- `description` — human-readable explanation of why the rule violates the requirement

### Pre-Sales Engineer Notes — What Tobias Richter Sees and Why It Answers PoC Objective 3

**PoC Objective 3 recap:** Harrington & Voss needs to demonstrate to its external PCI QSA that it has continuous, automated visibility into firewall rule compliance against PCI DSS Requirement 1 (firewall configuration standards). Manual audits are performed quarterly, leaving a 90-day blind spot between reviews. Tobias Richter (Head of Security Compliance) needs a solution that closes this gap.

**What Tobias sees in this report:**

1. **Cross-vendor, unified view:** The response aggregates violations from both the Fortinet perimeter firewall and the Check Point data centre gateway in a single list. Tobias does not need to export two separate audit reports from two separate management platforms and manually reconcile them. This is the core compliance value proposition in one API response.

2. **Requirement-level attribution:** Each violation is tagged to a specific PCI DSS requirement number (e.g., `Requirement 1.3.2`, `Requirement 7.1`). When Tobias hands this report to the QSA, the QSA can immediately map every finding to the relevant section of their audit questionnaire. This reduces audit preparation time from the current estimate of several weeks to hours.

3. **Severity triage:** The `severity: CRITICAL` flag on a rule that permits `src: Any` → `dst: CDE` with `service: Any` is the kind of finding that causes QSA audit failures. SecureTrack surfaces it in real time — not during the next quarterly review. For Tobias, this means **the audit finding exists in the remediation queue before the QSA arrives**, rather than being discovered on audit day.

4. **Continuous vs point-in-time:** Because SecureTrack polls device revisions continuously (on every detected policy change), the violation count in this report reflects the *current* state of the rule base, not a snapshot from the last manual review. If an engineer pushes a change tonight that introduces a new `src: Any` rule touching the CDE, SecureTrack will flag it within the next polling cycle — typically within minutes. This directly addresses the 90-day audit gap.

5. **Audit trail for the QSA:** Each `rule_id` and `device_id` in the response corresponds to a traceable record in SecureTrack's revision history. Tobias can show the QSA not just *that* a rule violates PCI DSS, but *when* it was introduced, *who* pushed the change (if SecureChange is in scope), and whether it has been certified by a rule owner. This is the difference between a reactive compliance posture and a demonstrable continuous compliance programme — which is precisely what PCI DSS v4.0 Requirement 12.3.2 now demands.

---

## API Call Summary Table

| # | Endpoint | Method | Status | Purpose |
|---|---|---|---|---|
| 1 | `/securetrack/api/devices?start=0&count=10` | GET | 200 | Inventory all managed devices; verify Fortinet + Check Point onboarding |
| 2 | `/securetrack/api/devices/1/rules?start=0&count=8` | GET | 200 | Retrieve Fortinet trading firewall ruleset; surface over-permissive rules |
| 3 | `/securetrack/api/devices/2/rules?start=0&count=9` | GET | 200 | Retrieve Check Point DC gateway ruleset; interpret layered policy structure |
| 4 | `/securetrack/api/topology/path?src=10.20.1.0/24&dst=10.50.2.0/24&service=tcp:443` | GET | 200 | Validate end-to-end trading path across both firewalls |
| 5 | `/securetrack/api/violating_rules?policy=PCI_DSS&start=0&count=100` | GET | 200 | Generate PCI DSS compliance report across all devices |

---

*Document prepared for Harrington & Voss PoC — Branch: `harrington-poc` — Last updated: 2025-06-03*
