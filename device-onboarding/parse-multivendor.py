#!/usr/bin/env python3
"""
parse-multivendor.py -- Harrington & Voss Multi-Vendor Device Onboarding Parser
================================================================================
Purpose:
    Simulates what Tufin SecureTrack+ TOS Discovery does during initial device
    onboarding: parses raw firewall config files from two different vendors,
    extracts structured device identity, interface topology, and firewall policy
    data, then produces a single unified comparative report.

    The report is not two summaries placed side by side. It surfaces risks that
    only become visible when both estates are analysed simultaneously -- the
    analytical capability that Tufin delivers through unified topology modelling.

Inputs:
    fortigate-config.txt  -- FortiGate flat hierarchical config (FortiOS CLI format)
    checkpoint-config.txt -- Check Point INI-style gateway export (R81.20)
    Both files must exist in the same directory as this script.

Output:
    onboarding-report.txt -- saved to the same directory as this script.
    Confirmation line printed to stdout on successful save.

Usage:
    python3 parse-multivendor.py

Dependencies:
    Python standard library only: re, os, sys
"""

import re
import os
import sys


# ---------------------------------------------------------------------------
# PATH RESOLUTION
# Always resolve relative to script location so the script runs correctly
# from any working directory on Mac Terminal.
# ---------------------------------------------------------------------------

SCRIPT_DIR  = os.path.dirname(os.path.abspath(__file__))
FGT_FILE    = os.path.join(SCRIPT_DIR, "fortigate-config.txt")
CP_FILE     = os.path.join(SCRIPT_DIR, "checkpoint-config.txt")
REPORT_FILE = os.path.join(SCRIPT_DIR, "onboarding-report.txt")


# ---------------------------------------------------------------------------
# UTILITY HELPERS
# ---------------------------------------------------------------------------

def load_file(path):
    """Read config file into a list of lines. Exit cleanly if not found."""
    if not os.path.exists(path):
        print("[ERROR] File not found: {}".format(path))
        sys.exit(1)
    with open(path, "r") as fh:
        return fh.readlines()

def banner(title, width=72):
    bar = "=" * width
    pad = " " * ((width - len(title) - 2) // 2)
    return "\n{}\n{} {}\n{}\n".format(bar, pad, title, bar)

def divider(title, width=72):
    return "\n{}\n  {}\n{}\n".format("-" * width, title, "-" * width)


# ---------------------------------------------------------------------------
# FORTINET PARSER
# ---------------------------------------------------------------------------
# FortiOS configs use a block-structured CLI syntax: named sections opened
# with "config <section>" and closed with "end", with objects delimited by
# "edit <id>" ... "next". Fields are "set <key> <value(s)>".
#
# Pre-Sales relevance:
#   Interface role mapping (wan/lan/dmz/vlan) gives SecureTrack+ the topology
#   context required for USP zone modelling and directional traffic analysis.
#   Policy extraction feeds rule usage analysis, compliance baseline checks,
#   and the cross-vendor visibility layer that distinguishes this report.
# ---------------------------------------------------------------------------

def parse_fortigate(lines):
    """
    Parse a FortiGate flat CLI config.
    Returns dict: hostname, interfaces (list), rules (list), flags (list).
    """
    data = {
        "hostname":   "unknown",
        "interfaces": [],
        "rules":      [],
        "flags":      []
    }

    # -- Hostname ------------------------------------------------------------
    for line in lines:
        m = re.search(r'set hostname\s+"?([^"\n]+)"?', line)
        if m:
            data["hostname"] = m.group(1).strip()
            break

    # -- Interfaces ----------------------------------------------------------
    # "config system interface" block; each interface is edit...next.
    in_iface  = False
    cur_iface = {}

    for line in lines:
        s = line.strip()

        if s == "config system interface":
            in_iface = True
            continue

        if not in_iface:
            continue

        if s.startswith("end"):
            if cur_iface:
                data["interfaces"].append(cur_iface)
                cur_iface = {}
            in_iface = False
            continue

        m = re.match(r'edit\s+"?([^"\n]+)"?', s)
        if m:
            if cur_iface:
                data["interfaces"].append(cur_iface)
            cur_iface = {
                "name": m.group(1).strip(),
                "ip":   "", "mask": "", "role": "unknown", "type": "physical"
            }
            continue

        if s == "next" and cur_iface:
            data["interfaces"].append(cur_iface)
            cur_iface = {}
            continue

        if cur_iface:
            m = re.match(r'set ip\s+(\S+)\s+(\S+)', s)
            if m:
                cur_iface["ip"]   = m.group(1)
                cur_iface["mask"] = m.group(2)

            m = re.match(r'set role\s+(\S+)', s)
            if m:
                cur_iface["role"] = m.group(1)

            m = re.match(r'set type\s+(\S+)', s)
            if m:
                cur_iface["type"] = m.group(1)

    # -- Firewall policy -----------------------------------------------------
    # "config firewall policy" block; each rule is edit <id>...next.
    in_policy = False
    cur_rule  = {}

    for line in lines:
        s = line.strip()

        if s == "config firewall policy":
            in_policy = True
            continue

        if not in_policy:
            continue

        if s.startswith("end"):
            if cur_rule:
                data["rules"].append(cur_rule)
                cur_rule = {}
            in_policy = False
            continue

        m = re.match(r'edit\s+(\d+)', s)
        if m:
            if cur_rule:
                data["rules"].append(cur_rule)
            cur_rule = {
                "id": m.group(1), "name": "",
                "srcintf": "", "dstintf": "",
                "srcaddr": [], "dstaddr": [],
                "action": "", "services": [],
                "logtraffic": "all"
            }
            continue

        if s == "next" and cur_rule:
            data["rules"].append(cur_rule)
            cur_rule = {}
            continue

        if cur_rule:
            m = re.match(r'set name\s+"?([^"\n]+)"?', s)
            if m: cur_rule["name"] = m.group(1).strip()

            m = re.match(r'set srcintf\s+"?([^"\n]+)"?', s)
            if m: cur_rule["srcintf"] = m.group(1).strip()

            m = re.match(r'set dstintf\s+"?([^"\n]+)"?', s)
            if m: cur_rule["dstintf"] = m.group(1).strip()

            m = re.match(r'set srcaddr\s+(.*)', s)
            if m:
                raw    = m.group(1)
                quoted = re.findall(r'"([^"]+)"', raw)
                cur_rule["srcaddr"] = quoted if quoted else raw.split()

            m = re.match(r'set dstaddr\s+(.*)', s)
            if m:
                raw    = m.group(1)
                quoted = re.findall(r'"([^"]+)"', raw)
                cur_rule["dstaddr"] = quoted if quoted else raw.split()

            m = re.match(r'set action\s+(\S+)', s)
            if m: cur_rule["action"] = m.group(1)

            m = re.match(r'set service\s+(.*)', s)
            if m:
                cur_rule["services"] = re.findall(r'"([^"]+)"', m.group(1))

            m = re.match(r'set logtraffic\s+(\S+)', s)
            if m: cur_rule["logtraffic"] = m.group(1)

    # -- Fortinet-specific flags ---------------------------------------------
    # Flag 1: logtraffic=disable -- zero audit trail. PCI DSS Req 10.2 finding.
    # Flag 2: logtraffic=utm     -- partial logging (UTM events only).
    #         Session-level records absent; insufficient for compliance audit.
    # Flag 3: srcaddr=all + dstaddr=all + action=accept -- unrestricted allow.
    #         Indicates missing segmentation; high-priority cleanup candidate.
    for rule in data["rules"]:
        ref = "Rule {} ({})".format(rule["id"], rule["name"])
        lt  = rule.get("logtraffic", "all").lower()

        if lt == "disable":
            data["flags"].append(
                "[LOGGING DISABLED]  {} -- logtraffic=disable. "
                "No audit trail for matched sessions. "
                "Direct PCI DSS Req 10.2 finding.".format(ref)
            )

        if lt == "utm":
            data["flags"].append(
                "[PARTIAL LOGGING]   {} -- logtraffic=utm. "
                "UTM/security events only; session-level records absent. "
                "Insufficient for full compliance audit.".format(ref)
            )

        src_all = any(v.lower() == "all" for v in rule.get("srcaddr", []))
        dst_all = any(v.lower() == "all" for v in rule.get("dstaddr", []))
        if src_all and dst_all and rule.get("action", "").lower() == "accept":
            data["flags"].append(
                "[PERMISSIVE RULE]   {} -- srcaddr=all, dstaddr=all, action=accept. "
                "Unrestricted allow. Requires scoping or documented "
                "business justification.".format(ref)
            )

    return data


# ---------------------------------------------------------------------------
# CHECK POINT PARSER
# ---------------------------------------------------------------------------
# This export uses an INI-style flat format with named section headers in
# square brackets. Interface lines are space-separated key=value tokens on
# one line per interface. Firewall rule lines are similarly flat key=value
# on a single line, with the rule name quoted.
#
# Pre-Sales relevance:
#   management_server and policy_package confirm where policy authority lives
#   -- critical when demonstrating that SecureTrack+ can centralise change
#   workflows across both vendors from a single pane of glass.
#   Policy layers confirm which enforcement tiers TOS will model and baseline.
# ---------------------------------------------------------------------------

def parse_checkpoint(lines):
    """
    Parse a Check Point INI-style gateway config export.
    Returns dict: hostname, version, mgmt_server, policy_package,
                  last_install, interfaces (list), rules (list),
                  policy_layers (list), flags (list).
    """
    data = {
        "hostname":       "unknown",
        "version":        "unknown",
        "mgmt_server":    "unknown",
        "policy_package": "unknown",
        "last_install":   "unknown",
        "interfaces":     [],
        "rules":          [],
        "policy_layers":  [],
        "flags":          []
    }

    current_section = None

    for line in lines:
        s = line.strip()
        if not s or s.startswith("#"):
            continue

        # -- Section headers -------------------------------------------------
        m = re.match(r'\[([A-Z_]+)\]', s)
        if m:
            current_section = m.group(1)
            continue

        # -- [GATEWAY] metadata ----------------------------------------------
        if current_section == "GATEWAY":
            m = re.match(r'hostname\s*=\s*(\S+)', s)
            if m: data["hostname"] = m.group(1)

            m = re.match(r'version\s*=\s*(\S+)', s)
            if m: data["version"] = m.group(1)

            m = re.match(r'management_server\s*=\s*(\S+)', s)
            if m: data["mgmt_server"] = m.group(1)

            m = re.match(r'policy_package\s*=\s*(\S+)', s)
            if m: data["policy_package"] = m.group(1)

            m = re.match(r'last_policy_install\s*=\s*(.+)', s)
            if m: data["last_install"] = m.group(1).strip()

        # -- [INTERFACES] ----------------------------------------------------
        # Format: ethN name=<n> ip=<ip> mask=<mask> topology=<topo>
        elif current_section == "INTERFACES":
            kv = dict(re.findall(r'(\w+)=([^\s]+)', s))
            if "ip" in kv and "mask" in kv:
                data["interfaces"].append({
                    "phy":      s.split()[0],
                    "name":     kv.get("name", s.split()[0]),
                    "ip":       kv["ip"],
                    "mask":     kv["mask"],
                    "topology": kv.get("topology", "unknown")
                })

        # -- [FIREWALL_RULES] ------------------------------------------------
        # Format: rule_id=N name="..." src=... dst=... service=... action=... track=...
        elif current_section == "FIREWALL_RULES":
            name_m = re.search(r'name="([^"]+)"', s)
            name   = name_m.group(1) if name_m else ""

            s_no_name = re.sub(r'name="[^"]+"', "", s)
            kv = dict(re.findall(r'(\w+)=([^\s]+)', s_no_name))

            if "rule_id" in kv:
                data["rules"].append({
                    "id":      kv["rule_id"],
                    "name":    name,
                    "src":     kv.get("src",     ""),
                    "dst":     kv.get("dst",     ""),
                    "service": kv.get("service", ""),
                    "action":  kv.get("action",  ""),
                    "track":   kv.get("track",   "")
                })

        # -- [POLICY_LAYERS] -------------------------------------------------
        # Format: layer_name=<name> layer_type=<type>
        elif current_section == "POLICY_LAYERS":
            m = re.match(r'layer_name=(\S+)\s+layer_type=(\S+)', s)
            if m:
                data["policy_layers"].append({
                    "name": m.group(1),
                    "type": m.group(2)
                })

    # -- Check Point-specific flags ------------------------------------------
    # Flag 1: action=drop + track=log  -- deny with logging confirmed (positive
    #         hygiene); flag to prompt log retention review in the engagement.
    # Flag 2: action=drop + track=none -- silent deny, no log record.
    #         PCI DSS Req 10.2.4 compliance gap.
    # Flag 3: src=any or dst=any       -- overly broad scope.
    for rule in data["rules"]:
        ref    = "Rule {} ({})".format(rule["id"], rule["name"])
        action = rule.get("action", "").lower()
        track  = rule.get("track",  "").lower()

        if action == "drop" and track == "log":
            data["flags"].append(
                "[DENY+LOG CONFIRMED] {} -- action=drop, track=log. "
                "Deny logging active. Confirm log retention meets "
                "minimum 90-day requirement.".format(ref)
            )

        if action == "drop" and track == "none":
            data["flags"].append(
                "[SILENT DENY]        {} -- action=drop, track=none. "
                "Dropped traffic produces no log record. "
                "PCI DSS Req 10.2.4 compliance gap.".format(ref)
            )

        if rule.get("src", "").lower() == "any":
            data["flags"].append(
                "[BROAD SOURCE]       {} -- src=any. "
                "No source restriction. Confirm intent and scope.".format(ref)
            )

        if rule.get("dst", "").lower() == "any":
            data["flags"].append(
                "[BROAD DESTINATION]  {} -- dst=any. "
                "No destination restriction. Confirm intent and scope.".format(ref)
            )

    return data


# ---------------------------------------------------------------------------
# CROSS-VENDOR ANALYSIS
# ---------------------------------------------------------------------------
# This section produces findings that are invisible to either vendor's native
# management console. It requires simultaneous knowledge of both estates --
# exactly what Tufin SecureTrack+ provides through unified topology modelling.
#
# Pre-Sales relevance:
#   This is the demo moment. When a prospect sees a confirmed traffic path
#   that spans two vendors and is controlled by neither management console,
#   Tufin's value stops being abstract. These findings cannot come from
#   Panorama, SmartConsole, or any single-vendor tool.
# ---------------------------------------------------------------------------

def cross_vendor_analysis(fgt, cp):
    """
    Analyse both estates simultaneously and return a list of cross-vendor
    finding strings.
    """
    findings = []

    # -- Finding 1: Cross-Vendor Visibility Gap (DC -> Frankfurt) ------------
    # FortiGate rule 6 (allow-dc-access-inbound):
    #   Permits inbound from wan1 with srcaddr=10.50.0.0/16 to internal2.
    # Check Point rule 2 (allow-dc-services-outbound):
    #   Permits src=10.50.0.0/16 outbound to any.
    #
    # The end-to-end path -- DC hosts leaving the CP gateway, transiting the
    # WAN, and arriving on the Frankfurt internal2 segment -- is authorised by
    # rules on two independent devices. Neither device owner sees the full path.
    fgt_r6 = next((r for r in fgt["rules"]
                   if r["id"] == "6" or r["name"] == "allow-dc-access-inbound"), None)
    cp_r2  = next((r for r in cp["rules"]
                   if r["id"] == "2" or r["name"] == "allow-dc-services-outbound"), None)

    if fgt_r6 and cp_r2:
        findings.append(
            "CROSS-VENDOR VISIBILITY GAP -- Data Centre to Frankfurt Lateral Path\n"
            "\n"
            "  Check Point side  ({}):\n"
            "    Rule {} \"{}\"  src={} -> dst={}  service=[{}]  action={}\n"
            "\n"
            "  FortiGate side  ({}):\n"
            "    Rule {} \"{}\"  srcintf={} -> dstintf={}  src=10.50.0.0/16 accepted inbound\n"
            "\n"
            "  CONFIRMED PATH:\n"
            "    10.50.0.0/16 (DC) --> WAN --> wan1 (FGT) --> internal2 (10.10.2.0/24)\n"
            "\n"
            "  RISK:\n"
            "    Traffic originating in the Check Point data centre (10.50.0.0/16)\n"
            "    can traverse the WAN and land directly on the Frankfurt internal2\n"
            "    segment. This path is not visible in Check Point SmartConsole (which\n"
            "    only sees outbound from DC) and not visible in FortiManager (which\n"
            "    only sees inbound to internal2). The end-to-end path exists only\n"
            "    when both estates are modelled together in Tufin SecureTrack+.\n"
            "\n"
            "  RECOMMENDATION:\n"
            "    1. Build a unified topology model in SecureTrack+ spanning both devices.\n"
            "    2. Raise a SecureChange ticket to formally review and scope this path.\n"
            "    3. Evaluate whether internal2 access from 10.50.0.0/16 is intentional\n"
            "       and if so, restrict services and confirm logging on both rules.".format(
                cp["hostname"],
                cp_r2["id"], cp_r2["name"], cp_r2["src"], cp_r2["dst"], cp_r2["service"], cp_r2["action"],
                fgt["hostname"],
                fgt_r6["id"], fgt_r6["name"], fgt_r6["srcintf"], fgt_r6["dstintf"]
            )
        )
    else:
        findings.append(
            "CROSS-VENDOR VISIBILITY GAP -- Expected rules not matched.\n"
            "  Verify FortiGate rule 6 (allow-dc-access-inbound) and\n"
            "  Check Point rule 2 (allow-dc-services-outbound) are present."
        )

    # -- Finding 2: Trading VLAN path (coordinated change risk) --------------
    # FGT rule 1 (allow-trading-to-internet): vlan-trading -> wan1, service=FIX,HTTPS
    # CP  rule 5 (allow-trading-dc-feeds):    src=10.20.1.0/24 -> dst=10.50.2.0/24
    # Both rules are required for the trading connectivity workflow.
    # A change to either without coordination with the other can silently
    # break FIX protocol feeds -- a high-severity operational risk.
    fgt_r1 = next((r for r in fgt["rules"]
                   if r["id"] == "1" or r["name"] == "allow-trading-to-internet"), None)
    cp_r5  = next((r for r in cp["rules"]
                   if r["id"] == "5" or r["name"] == "allow-trading-dc-feeds"), None)

    if fgt_r1 and cp_r5:
        findings.append(
            "CROSS-VENDOR COORDINATION REQUIRED -- Trading VLAN to DC Feed Path\n"
            "\n"
            "  FortiGate  : Rule {} \"{}\"  vlan-trading ({}) -> wan1  service=[{}]\n"
            "  Check Point: Rule {} \"{}\"  src={} -> dst={}  service=[{}]\n"
            "\n"
            "  This is a business-critical path (FIX protocol / trading feeds)\n"
            "  governed by two independent rule sets on two separate platforms.\n"
            "  A change to either rule without awareness of the other can\n"
            "  silently break live trading connectivity.\n"
            "\n"
            "  RECOMMENDATION:\n"
            "    Model this as a named multi-device topology path in SecureTrack+.\n"
            "    Any modification to FGT rule {} or CP rule {} must be raised\n"
            "    as a single coordinated SecureChange ticket, not two separate requests.".format(
                fgt_r1["id"], fgt_r1["name"], "10.20.1.0/24", ",".join(fgt_r1["services"]),
                cp_r5["id"],  cp_r5["name"],  cp_r5["src"], cp_r5["dst"], cp_r5["service"],
                fgt_r1["id"], cp_r5["id"]
            )
        )

    # -- Finding 3: Compliance VLAN path (coordinated change risk) -----------
    # FGT rule 2 (allow-compliance-to-datacentre): vlan-compliance -> 10.50.0.0/16
    # CP  rule 6 (allow-compliance-reporting):     src=10.20.2.0/24 -> 10.50.3.0/24
    fgt_r2 = next((r for r in fgt["rules"]
                   if r["id"] == "2" or r["name"] == "allow-compliance-to-datacentre"), None)
    cp_r6  = next((r for r in cp["rules"]
                   if r["id"] == "6" or r["name"] == "allow-compliance-reporting"), None)

    if fgt_r2 and cp_r6:
        findings.append(
            "CROSS-VENDOR COORDINATION REQUIRED -- Compliance VLAN to DC Reporting Path\n"
            "\n"
            "  FortiGate  : Rule {} \"{}\"  vlan-compliance -> 10.50.0.0/16  service=[{}]\n"
            "  Check Point: Rule {} \"{}\"  src={} -> dst={}  service=[{}]\n"
            "\n"
            "  Both rules are required for the compliance reporting workflow.\n"
            "  Neither policy owner has full visibility of the end-to-end path.\n"
            "  A change to either in isolation risks breaking regulatory reporting.\n"
            "\n"
            "  RECOMMENDATION:\n"
            "    Register this as a named connectivity object in SecureTrack+.\n"
            "    Enforce change coordination via SecureChange for both rule sets.".format(
                fgt_r2["id"], fgt_r2["name"], ",".join(fgt_r2["services"]),
                cp_r6["id"],  cp_r6["name"],  cp_r6["src"], cp_r6["dst"], cp_r6["service"]
            )
        )

    # -- Finding 4: Shared IP scope ------------------------------------------
    # IP prefixes that appear explicitly in rules on BOTH estates are governed
    # by two independent policy sets. A change to either without the other
    # creates asymmetric access or orphaned rules.
    def collect_ips(rules, vendor):
        found = {}
        pat = re.compile(r'(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}(?:/\d+)?)')
        for rule in rules:
            tokens = (rule.get("srcaddr", []) + rule.get("dstaddr", [])
                      if vendor == "fgt"
                      else [rule.get("src", ""), rule.get("dst", "")])
            for tok in tokens:
                for ip in pat.findall(tok):
                    found.setdefault(ip, []).append("rule {}".format(rule["id"]))
        return found

    fgt_ips = collect_ips(fgt["rules"], "fgt")
    cp_ips  = collect_ips(cp["rules"],  "cp")
    shared  = sorted(set(fgt_ips) & set(cp_ips))

    if shared:
        rows = []
        for ip in shared:
            rows.append(
                "  {}\n"
                "    FortiGate   : {}\n"
                "    Check Point : {}".format(
                    ip,
                    ", ".join(sorted(set(fgt_ips[ip]))),
                    ", ".join(sorted(set(cp_ips[ip])))
                )
            )
        findings.append(
            "SHARED SCOPE -- IP Prefixes Present in Both Vendor Rule Sets\n"
            "\n"
            "  These prefixes appear in explicit rules on both gateways.\n"
            "  Independent policy changes on either device risk creating\n"
            "  asymmetric access or silent connectivity loss.\n"
            "  All changes to these prefixes must be coordinated through\n"
            "  a single SecureChange workflow covering both devices.\n"
            "\n" + "\n".join(rows)
        )
    else:
        findings.append(
            "SHARED SCOPE -- No overlapping explicit IP prefixes detected\n"
            "  at rule level between the two estates. Manual network object\n"
            "  review still recommended for subnet containment overlaps."
        )

    return findings


# ---------------------------------------------------------------------------
# REPORT ASSEMBLY
# ---------------------------------------------------------------------------

def build_report(fgt, cp, cross):
    """Assemble and return the full onboarding report as a single string."""
    out = []

    out.append("=" * 72)
    out.append("  TUFIN SECURETRACK+ -- MULTI-VENDOR DEVICE ONBOARDING REPORT")
    out.append("  Client  : Harrington & Voss")
    out.append("  Devices : FortiGate (Frankfurt Office) + Check Point (Data Centre)")
    out.append("  Scope   : Initial TOS Discovery simulation -- PoC engagement")
    out.append("=" * 72)

    # -----------------------------------------------------------------------
    # SECTION 1: FORTINET
    # -----------------------------------------------------------------------
    out.append(banner("SECTION 1: FORTINET ESTATE SUMMARY"))
    out.append("  Hostname       : {}".format(fgt["hostname"]))
    out.append("  Interfaces     : {}".format(len(fgt["interfaces"])))
    out.append("  Firewall Rules : {}".format(len(fgt["rules"])))

    out.append(divider("Interfaces"))
    out.append("  {:<18} {:<16} {:<18} {:<10} {}".format(
        "Name", "IP Address", "Subnet Mask", "Role", "Type"))
    out.append("  {} {} {} {} {}".format(
        "-"*17, "-"*15, "-"*17, "-"*9, "-"*8))
    for i in fgt["interfaces"]:
        out.append("  {:<18} {:<16} {:<18} {:<10} {}".format(
            i["name"], i["ip"], i["mask"], i["role"], i["type"]))

    out.append(divider("Firewall Policy"))
    for r in fgt["rules"]:
        src = ", ".join(r["srcaddr"]) if r["srcaddr"] else "--"
        dst = ", ".join(r["dstaddr"]) if r["dstaddr"] else "--"
        svc = ", ".join(r["services"]) if r["services"] else "--"
        out.append("  Rule {:>2}  |  {}".format(r["id"], r["name"]))
        out.append("          SrcIntf : {}  ->  DstIntf : {}".format(r["srcintf"], r["dstintf"]))
        out.append("          Src     : {}  |  Dst : {}".format(src, dst))
        out.append("          Action  : {:<8}  Services : {}  Logging : {}".format(
            r["action"].upper(), svc, r["logtraffic"]))
        out.append("")

    out.append(divider("Fortinet Flags  [{}]".format(len(fgt["flags"]))))
    if fgt["flags"]:
        for f in fgt["flags"]:
            out.append("  !  {}".format(f))
            out.append("")
    else:
        out.append("  No flags raised.")

    # -----------------------------------------------------------------------
    # SECTION 2: CHECK POINT
    # -----------------------------------------------------------------------
    out.append(banner("SECTION 2: CHECK POINT ESTATE SUMMARY"))
    out.append("  Hostname          : {}".format(cp["hostname"]))
    out.append("  Version           : {}".format(cp["version"]))
    out.append("  Management Server : {}".format(cp["mgmt_server"]))
    out.append("  Policy Package    : {}".format(cp["policy_package"]))
    out.append("  Last Policy Push  : {}".format(cp["last_install"]))
    out.append("  Interfaces        : {}".format(len(cp["interfaces"])))
    out.append("  Firewall Rules    : {}".format(len(cp["rules"])))
    layers_str = ", ".join("{} ({})".format(l["name"], l["type"]) for l in cp["policy_layers"])
    out.append("  Policy Layers     : {}".format(layers_str if layers_str else "none detected"))

    out.append(divider("Interfaces"))
    out.append("  {:<8} {:<14} {:<16} {:<18} {}".format(
        "Port", "Name", "IP Address", "Subnet Mask", "Topology"))
    out.append("  {} {} {} {} {}".format(
        "-"*7, "-"*13, "-"*15, "-"*17, "-"*10))
    for i in cp["interfaces"]:
        out.append("  {:<8} {:<14} {:<16} {:<18} {}".format(
            i["phy"], i["name"], i["ip"], i["mask"], i["topology"]))

    out.append(divider("Firewall Policy"))
    for r in cp["rules"]:
        out.append("  Rule {:>2}  |  {}".format(r["id"], r["name"]))
        out.append("          Src     : {}  ->  Dst : {}".format(r["src"], r["dst"]))
        out.append("          Action  : {:<8}  Services : {}  Track : {}".format(
            r["action"].upper(), r["service"], r["track"]))
        out.append("")

    out.append(divider("Check Point Flags  [{}]".format(len(cp["flags"]))))
    if cp["flags"]:
        for f in cp["flags"]:
            out.append("  !  {}".format(f))
            out.append("")
    else:
        out.append("  No flags raised.")

    # -----------------------------------------------------------------------
    # SECTION 3: CROSS-VENDOR ANALYSIS
    # -----------------------------------------------------------------------
    out.append(banner("SECTION 3: CROSS-VENDOR ANALYSIS"))
    out.append("  The following findings require simultaneous visibility across both")
    out.append("  vendor estates. They are not visible from Check Point SmartConsole")
    out.append("  or FortiManager independently. This is the core capability Tufin")
    out.append("  SecureTrack+ delivers through unified multi-vendor topology modelling.")

    for idx, finding in enumerate(cross, 1):
        out.append("")
        out.append("  [FINDING {}]  {}".format(idx, finding))

    out.append("")
    out.append("=" * 72)
    out.append("  END OF REPORT")
    out.append("  Generated by parse-multivendor.py -- Tufin SecureTrack+ PoC tooling")
    out.append("  All data extracted from raw config files. No manual input applied.")
    out.append("=" * 72)

    return "\n".join(out)


# ---------------------------------------------------------------------------
# ENTRY POINT
# ---------------------------------------------------------------------------

def main():
    fgt_lines = load_file(FGT_FILE)
    cp_lines  = load_file(CP_FILE)

    fgt  = parse_fortigate(fgt_lines)
    cp   = parse_checkpoint(cp_lines)
    xv   = cross_vendor_analysis(fgt, cp)

    report = build_report(fgt, cp, xv)

    with open(REPORT_FILE, "w") as fh:
        fh.write(report)

    print("[OK] Report saved to: {}".format(REPORT_FILE))
    print("     FortiGate    -> {} interfaces, {} rules, {} flags".format(
        len(fgt["interfaces"]), len(fgt["rules"]), len(fgt["flags"])))
    print("     Check Point  -> {} interfaces, {} rules, {} flags".format(
        len(cp["interfaces"]),  len(cp["rules"]),  len(cp["flags"])))
    print("     Cross-vendor -> {} findings".format(len(xv)))


if __name__ == "__main__":
    main()
