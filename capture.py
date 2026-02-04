# file: capture.py
"""
Packet capture and synthetic generator tuned for testing signatures.
Generates TCP (including SYN bursts), UDP, and ICMP (incoming/outgoing) traffic
with patterns that exercise SYN_FLOOD, PORT_SCAN, HIGH_RATE, and PING_FLOOD.
"""
from typing import Dict, Any
import os
import time
import queue
import random
import csv
from collections import defaultdict, deque
from statistics import mean
from dashboard import blocked_ips
import config

# Attempt scapy import; if unavailable we enable TEST_MODE
SCAPY_OK = True
try:
    from scapy.all import sniff
    from scapy.layers.inet import IP, TCP, UDP, ICMP
except Exception:
    SCAPY_OK = False

# TEST_MODE flag
TEST_MODE = os.environ.get("TEST_MODE", "0") == "1" or not SCAPY_OK

# Queue: sniffer/generator -> detector
record_queue: queue.Queue = queue.Queue(maxsize=10000)

# Sliding windows for per-src tracking
last_seen: Dict[str, float] = {}
ip_windows: Dict[str, deque] = defaultdict(lambda: deque())  # src_ip -> deque of (timestamp,dst_port,len,flags)

# Local IPs (treat these as "incoming" targets)
LOCAL_IPS = ["128.0.1.108"]

def now() -> float:
    return time.time()

# Ensure CSV header exists
def ensure_csv_header() -> None:
    if not os.path.exists(config.CAPTURE_CSV):
        with open(config.CAPTURE_CSV, "w", newline="") as f:
            csv.writer(f).writerow(config.CSV_COLUMNS)

ensure_csv_header()

def append_record_csv(rec: Dict[str, Any]) -> None:
    try:
        with open(config.CAPTURE_CSV, "a", newline="") as f:
            csv.writer(f).writerow([rec.get(c, "") for c in config.CSV_COLUMNS])
    except Exception:
        pass

def packet_to_record(pkt) -> Dict[str, Any]:
    """
    Convert a scapy packet to the record dict (or None if unsupported).
    Works for live sniffer and synthetic objects that mimic fields.
    """
    try:
        if not pkt.haslayer(IP):
            return None
        ts = now()
        ip = pkt[IP]
        src = ip.src
        dst = ip.dst
        proto = int(getattr(ip, "proto", 0) or 0)
        src_port = 0
        dst_port = 0
        tcp_flags = 0

        if proto == 6 and pkt.haslayer(TCP):
            tcp = pkt[TCP]
            src_port = int(getattr(tcp, "sport", 0) or 0)
            dst_port = int(getattr(tcp, "dport", 0) or 0)
            tcp_flags = int(getattr(tcp, "flags", 0) or 0)
        elif proto == 17 and pkt.haslayer(UDP):
            udp = pkt[UDP]
            src_port = int(getattr(udp, "sport", 0) or 0)
            dst_port = int(getattr(udp, "dport", 0) or 0)
        elif proto == 1:
            src_port = 0
            dst_port = 0

        pkt_len = len(pkt)
        tdelta = ts - last_seen.get(src, ts)
        last_seen[src] = ts

        # Update sliding window
        win = ip_windows[src]
        win.append((ts, dst_port, pkt_len, tcp_flags))
        cutoff = ts - config.WINDOW_SECONDS
        while win and win[0][0] < cutoff:
            win.popleft()

        packets_per_sec = len(win) / max(1.0, config.WINDOW_SECONDS)
        unique_dst_ports = len({p for (_t, p, _l, _s) in win if p is not None})
        avg_packet_len = float(mean([l for (_t, _p, l, _s) in win])) if win else float(pkt_len)

        record = {
            "timestamp": ts,
            "src_ip": src,
            "dst_ip": dst,
            "src_port": int(src_port),
            "dst_port": int(dst_port),
            "protocol": int(proto),
            "packet_len": int(pkt_len),
            "tcp_flags": int(tcp_flags),
            "time_delta": float(tdelta),
            "packets_per_sec": float(packets_per_sec),
            "unique_dst_ports": int(unique_dst_ports),
            "avg_packet_len": float(avg_packet_len),
        }
        return record
    except Exception:
        return None

def handle_packet(pkt):
    rec = packet_to_record(pkt)
    if rec is None:
        return

    if rec.get("src_ip") in blocked_ips:
        return
    try:
        record_queue.put_nowait(rec)
    except queue.Full:
        # drop if overwhelmed
        pass

def sniffer_thread():
    # Minimal output; live sniffing requires privileges
    try:
        sniff(filter=config.PCAP_FILTER, prn=handle_packet, store=False, iface=config.INTERFACE)
    except Exception:
        pass

def synthetic_record_generator(interval: float = 0.01):
    """
    Synthetic traffic that will trigger signatures for testing:
      - SYN bursts (SYN_FLOOD)
      - Port scanning from a source (PORT_SCAN)
      - High rate bursts (HIGH_RATE)
      - ICMP incoming pings (PING_PACKET) and occasional ping flood (PING_FLOOD)
    """
    rng = random.Random(12345)
    src_pool = [f"192.168.1.{i}" for i in range(2, 40)]
    dst_pool = [f"10.0.0.{i}" for i in range(2, 40)]
    scan_ports = list(range(1000, 1012))  # small port set for port-scan testing

    while True:
        ts = now()

        # Choose a behavior probabilistically to ensure variety
        mode = rng.random()

        if mode < 0.10:
            # SYN flood burst from single attacker src -> many dst ports
            attacker = rng.choice(src_pool)
            for _ in range(8):  # send multiple SYNs quickly (enough for low test thresholds)
                sport = rng.randint(1024, 65535)
                dport = rng.randint(1000, 1100)
                rec = {
                    "timestamp": now(),
                    "src_ip": attacker,
                    "dst_ip": rng.choice(dst_pool),
                    "src_port": sport,
                    "dst_port": dport,
                    "protocol": 6,            # TCP
                    "packet_len": 60,
                    "tcp_flags": 0x02,       # SYN
                    "time_delta": 0.0,
                }
                last_seen[attacker] = rec["timestamp"]
                # update window directly here (so detector sees it in queue processing)
                if rec.get("src_ip") in blocked_ips:
                    continue
                try:
                    record_queue.put_nowait(rec)
                except queue.Full:
                    pass
            # small sleep to create burst pattern
            time.sleep(interval * 3)
            continue

        if mode < 0.25:
            # Port scan: one source hits many distinct dst ports
            scanner = rng.choice(src_pool)
            dst = rng.choice(dst_pool)
            # iterate over small scan_ports to create unique port set
            for p in scan_ports:
                rec = {
                    "timestamp": now(),
                    "src_ip": scanner,
                    "dst_ip": dst,
                    "src_port": rng.randint(1024, 65535),
                    "dst_port": p,
                    "protocol": 6,         # TCP (but could be UDP too)
                    "packet_len": 60,
                    "tcp_flags": 0x02 if rng.random() < 0.7 else 0x00,
                    "time_delta": 0.0,
                }
                last_seen[scanner] = rec["timestamp"]
                try:
                    record_queue.put_nowait(rec)
                except queue.Full:
                    pass
            time.sleep(interval * 2)
            continue

        if mode < 0.45:
            # High-rate small packets from a source
            burst_src = rng.choice(src_pool)
            for _ in range(25):  # a tight burst to exceed RATE_THRESHOLD in test
                rec = {
                    "timestamp": now(),
                    "src_ip": burst_src,
                    "dst_ip": rng.choice(dst_pool),
                    "src_port": rng.randint(1024, 65535),
                    "dst_port": rng.randint(2000, 3000),
                    "protocol": rng.choice([6,17]),
                    "packet_len": 100,
                    "tcp_flags": 0x00,
                    "time_delta": 0.0,
                }
                last_seen[burst_src] = rec["timestamp"]
                try:
                    record_queue.put_nowait(rec)
                except queue.Full:
                    pass
            time.sleep(interval * 2)
            continue

        # Default: normal traffic mixed (includes ICMP incoming sometimes)
        src = rng.choice(src_pool)
        dst = rng.choice(dst_pool)
        proto = rng.choice([6,17,1,1,6])  # weight ICMP a bit higher for testing
        tcp_flags = 0
        src_port = 0
        dst_port = 0
        if proto == 6:
            src_port = rng.randint(1024, 65535)
            dst_port = rng.randint(1024, 65535)
            # occasional SYN
            if rng.random() < 0.05:
                tcp_flags = 0x02
        elif proto == 17:
            src_port = rng.randint(1024, 65535)
            dst_port = rng.randint(1024, 65535)
        elif proto == 1:
            # make ~50% of ICMP target a LOCAL_IP to simulate incoming ping
            if rng.random() < 0.5:
                dst = rng.choice(LOCAL_IPS)

        pkt_len = max(40, int(rng.gauss(200, 100)))
        rec = {
            "timestamp": ts,
            "src_ip": src,
            "dst_ip": dst,
            "src_port": int(src_port),
            "dst_port": int(dst_port),
            "protocol": int(proto),
            "packet_len": int(pkt_len),
            "tcp_flags": int(tcp_flags),
            "time_delta": ts - last_seen.get(src, ts),
        }
        last_seen[src] = ts
        try:
            record_queue.put_nowait(rec)
        except queue.Full:
            pass

        # small random jitter between synthetic packets
        time.sleep(interval * (0.5 + rng.random()))
