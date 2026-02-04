# file: config.py
"""
Shared configuration for Signature-based IDS with optional blocking.
Adjust BLOCK settings carefully for your environment.
"""
import os

DATA_DIR = "data"
os.makedirs(DATA_DIR, exist_ok=True)
CAPTURE_CSV = os.path.join(DATA_DIR, "captured.csv")

INTERFACE = None  # e.g. "eth0" or None for default
PCAP_FILTER = "ip and (tcp or udp or icmp)"

# Sliding window thresholds (tune for your lab)
WINDOW_SECONDS = 2
SYN_THRESHOLD = 5
PORTSCAN_UNIQUE_PORTS = 5
RATE_THRESHOLD = 20

# CSV columns
CSV_COLUMNS = [
    "timestamp","src_ip","dst_ip","src_port","dst_port","protocol",
    "packet_len","tcp_flags","time_delta","packets_per_sec",
    "unique_dst_ports","avg_packet_len"
]

# ---------------- Blocking configuration ----------------
# WARNING: Blocking executes system commands. Use with care.
# If False, block/unblock endpoints will refuse to run commands.
ALLOW_BLOCKING = True    # set to False to disable actual blocking (safe mode)

# Templates. These are shell commands where '{ip}' will be replaced.
# Default uses iptables on Linux. You can replace with nftables, firewalld calls, or custom scripts.
# In config.py
BLOCK_CMD_TEMPLATE = 'netsh advfirewall firewall add rule name="IDS_Block_{ip}" dir=in action=block remoteip={ip}'
UNBLOCK_CMD_TEMPLATE = 'netsh advfirewall firewall delete rule name="IDS_Block_{ip}"'

# Optional: dry-run mode (only for extra safety; commands won't be executed even if ALLOW_BLOCKING is True)
DRY_RUN_BLOCKING = False
