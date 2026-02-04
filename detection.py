# file: detection.py
"""
Signature-based IDS with DDoS signatures and actionable alerts.
Alerts include fields required by dashboard. This module does not perform blocking.
Blocking is handled by dashboard.block_ip/unblock_ip which require user confirmation.
"""
from typing import Dict, Any, Callable, List
from collections import deque, defaultdict
import time

from capture import record_queue, ip_windows
import config

# Delete/adjust previous signature constants if needed; keep them similar to previous
SIGNATURES = [
    {"name": "SYN_FLOOD", "protocol": "TCP", "min_syn": config.SYN_THRESHOLD, "severity": "CRITICAL"},
    {"name": "PORT_SCAN", "protocol": "TCP/UDP", "min_unique_ports": config.PORTSCAN_UNIQUE_PORTS, "severity": "CRITICAL"},
    {"name": "HIGH_RATE", "protocol": "TCP/UDP", "min_pps": config.RATE_THRESHOLD, "severity": "WARNING"},
    {"name": "PING_PACKET", "protocol": "ICMP", "severity": "WARNING", "incoming_only": True},
    {"name": "PING_FLOOD", "protocol": "ICMP", "min_count": 50, "severity": "CRITICAL", "incoming_only": True},
    # DDoS-specific simple signatures (defaults can be tuned)
    {"name": "UDP_FLOOD", "protocol": "UDP", "min_pps": 200, "severity": "CRITICAL"},
    {"name": "ICMP_FLOOD", "protocol": "ICMP", "min_pps": 200, "severity": "CRITICAL"},
    {"name": "AMP_DNS", "protocol": "UDP", "dst_port": 53, "min_len": 200, "min_count": 20, "severity": "CRITICAL"},
    {"name": "AMP_NTP", "protocol": "UDP", "dst_port": 123, "min_len": 200, "min_count": 20, "severity": "CRITICAL"},
    {"name": "DDOS_MULTI_SRC", "protocol": "ANY", "min_distinct_srcs": 20, "min_pps": 50, "severity": "CRITICAL"},
]

# Per-destination windows for DDoS checks
dst_windows: Dict[str, deque] = defaultdict(lambda: deque())

# Suppression to limit alert spam
SUPPRESSION_SECONDS = 30
last_alert_ts: Dict[tuple, float] = {}

def suppressed(key: tuple) -> bool:
    last = last_alert_ts.get(key)
    if last is None:
        return False
    return (time.time() - last) < SUPPRESSION_SECONDS

def mark_alert(key: tuple) -> None:
    last_alert_ts[key] = time.time()

def make_alert(trigger: str, severity: str, evidence: Any, src_ip: str, dst_ip: str, ts: float) -> Dict[str, Any]:
    return {
        "trigger": trigger,
        "severity": severity,
        "evidence": evidence,
        "src_ip": src_ip,
        "dst_ip": dst_ip,
        "ts": ts
    }

def check_signature(rec: Dict[str, Any]) -> List[Dict[str, Any]]:
    alerts = []
    proto = rec.get("protocol", 0)
    src = rec.get("src_ip", "0.0.0.0")
    dst = rec.get("dst_ip", "0.0.0.0")
    ts = rec.get("timestamp", time.time())
    dst_port = rec.get("dst_port", 0)
    pkt_len = rec.get("packet_len", 0)
    tcp_flags = rec.get("tcp_flags", 0)

    # Update windows
    swin = ip_windows.setdefault(src, deque())
    swin.append((ts, dst_port, pkt_len, tcp_flags))
    cutoff = ts - config.WINDOW_SECONDS
    while swin and swin[0][0] < cutoff:
        swin.popleft()

    dwin = dst_windows.setdefault(dst, deque())
    dwin.append((ts, src, dst_port, pkt_len, proto))
    while dwin and dwin[0][0] < cutoff:
        dwin.popleft()

    for sig in SIGNATURES:
        name = sig["name"]

        # SYN flood (per source)
        if name == "SYN_FLOOD" and proto == 6:
            syn_count = sum(1 for (_t,_p,_l,_f) in list(swin) if _f & 0x02)
            if syn_count >= sig["min_syn"]:
                key = (name, src)
                if not suppressed(key):
                    alerts.append(make_alert(name, sig["severity"], {"syn_count": syn_count}, src, dst, ts))
                    mark_alert(key)

        # PORT_SCAN
        elif name == "PORT_SCAN" and proto in (6,17):
            unique_ports = len({p for (_t,p,_l,_f) in list(swin)})
            if unique_ports >= sig["min_unique_ports"]:
                key = (name, src)
                if not suppressed(key):
                    alerts.append(make_alert(name, sig["severity"], {"unique_dst_ports": unique_ports}, src, dst, ts))
                    mark_alert(key)

        # HIGH_RATE
        elif name == "HIGH_RATE" and proto in (6,17):
            pps = len(swin) / max(1.0, config.WINDOW_SECONDS)
            if pps >= sig["min_pps"]:
                key = (name, src)
                if not suppressed(key):
                    alerts.append(make_alert(name, sig["severity"], {"packets_per_sec": pps}, src, dst, ts))
                    mark_alert(key)

        # ICMP incoming ping
        elif name == "PING_PACKET" and proto == 1:
            if sig.get("incoming_only") and dst not in getattr(config, "LOCAL_IPS", []):
                pass
            else:
                key = (name, dst)
                if not suppressed(key):
                    alerts.append(make_alert(name, sig["severity"], {"pkt_len": pkt_len}, src, dst, ts))
                    mark_alert(key)

        # PING_FLOOD per source
        elif name == "PING_FLOOD" and proto == 1 and sig.get("min_count"):
            icmp_count_src = sum(1 for (_t,_p,_l,_f) in swin if True)  # counts all pkts in swin; fine for lab
            if icmp_count_src >= sig["min_count"]:
                key = (name, src)
                if not suppressed(key):
                    alerts.append(make_alert(name, sig["severity"], {"icmp_count": icmp_count_src}, src, dst, ts))
                    mark_alert(key)

        # UDP_FLOOD (per destination)
        elif name == "UDP_FLOOD" and proto == 17:
            dest_pps = sum(1 for (_t,_s,_p,_l,_pr) in dwin) / max(1.0, config.WINDOW_SECONDS)
            if dest_pps >= sig["min_pps"]:
                key = (name, dst)
                if not suppressed(key):
                    alerts.append(make_alert(name, sig["severity"], {"dest_pps": dest_pps}, src, dst, ts))
                    mark_alert(key)

        # ICMP_FLOOD (per destination)
        elif name == "ICMP_FLOOD" and proto == 1:
            dest_pps = sum(1 for (_t,_s,_p,_l,_pr) in dwin if _pr == 1) / max(1.0, config.WINDOW_SECONDS)
            if dest_pps >= sig["min_pps"]:
                key = (name, dst)
                if not suppressed(key):
                    alerts.append(make_alert(name, sig["severity"], {"dest_pps": dest_pps}, src, dst, ts))
                    mark_alert(key)

        # Amplification candidates
        elif name in ("AMP_DNS", "AMP_NTP") and proto == 17:
            expected = sig.get("dst_port")
            if expected is None:
                continue
            amp_count = sum(1 for (_t,_s,_p,_l,_pr) in dwin if _p == expected and _l >= sig.get("min_len", 0))
            if amp_count >= sig.get("min_count", 0):
                key = (name, dst)
                if not suppressed(key):
                    alerts.append(make_alert(name, sig["severity"], {"amp_count": amp_count, "dst_port": expected}, src, dst, ts))
                    mark_alert(key)

        # Multi-source DDoS (many distinct srcs to same dst)
        elif name == "DDOS_MULTI_SRC":
            dest_pps = len(dwin) / max(1.0, config.WINDOW_SECONDS)
            distinct_srcs = len({_s for (_t,_s,_p,_l,_pr) in dwin})
            if dest_pps >= sig.get("min_pps", 0) and distinct_srcs >= sig.get("min_distinct_srcs", 0):
                key = (name, dst)
                if not suppressed(key):
                    alerts.append(make_alert(name, sig["severity"], {"dest_pps": dest_pps, "distinct_srcs": distinct_srcs}, src, dst, ts))
                    mark_alert(key)

    return alerts

def detector_loop(push_alert: Callable[[Dict[str, Any]], None]):
    print("Detector with DDoS signatures started.")
    last_heartbeat = time.time()
    while True:
        # heartbeat suppressed in production
        if time.time() - last_heartbeat > 30:
            last_heartbeat = time.time()
        try:
            rec = record_queue.get(timeout=1)
        except Exception:
            continue
        alerts = check_signature(rec)
        for a in alerts:
            # ensure top-level fields for dashboard
            a.setdefault("src_ip", rec.get("src_ip", "0.0.0.0"))
            a.setdefault("dst_ip", rec.get("dst_ip", "0.0.0.0"))
            a.setdefault("ts", rec.get("timestamp", time.time()))
            try:
                if a["severity"] in ("CRITICAL", "WARNING"):
                    push_alert(a)
            except Exception:
                pass
