#!/usr/bin/env python3
"""
find_ip.py

Finds local IP(s) for the current device and (optionally) the public IP.

Usage:
    python find_ip.py           # show hostname, primary local IP, all local IPs
    python find_ip.py --public  # also try to fetch public IP via api.ipify.org
"""

import socket
import argparse
import urllib.request
import urllib.error


def get_hostname() -> str:
    return socket.gethostname()


def get_primary_local_ip(timeout: float = 1.0) -> str:
    """
    Returns the IP address of the interface that would be used to reach the Internet.
    Uses a UDP "connect" to a public IP — no packets are sent.
    """
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
            s.settimeout(timeout)
            # Use a public IP (Google DNS); no packet is actually sent.
            s.connect(("8.8.8.8", 80))
            ip = s.getsockname()[0]
            return ip
    except Exception:
        return "127.0.0.1"


def get_all_local_ips() -> list:
    """
    Returns all non-loopback IP addresses associated with the host name.
    This uses getaddrinfo on the local hostname. It may return IPv4 and IPv6.
    """
    ips = set()
    try:
        hostname = get_hostname()
        for res in socket.getaddrinfo(hostname, None, proto=socket.IPPROTO_TCP):
            ip = res[4][0]
            # filter out pure loopback
            if ip.startswith("127.") or ip == "::1":
                continue
            ips.add(ip)
    except Exception:
        pass

    # As a fallback, also include the primary ip
    try:
        primary = get_primary_local_ip()
        if primary and not primary.startswith("127."):
            ips.add(primary)
    except Exception:
        pass

    return sorted(ips)


def get_public_ip(timeout: float = 3.0) -> str:
    """
    Queries a public service to get the external IP address.
    Uses api.ipify.org (simple plain-text response).
    May fail if offline or outbound HTTP is blocked.
    """
    try:
        with urllib.request.urlopen("https://api.ipify.org", timeout=timeout) as r:
            return r.read().decode().strip()
    except urllib.error.URLError as e:
        return f"error: {e}"
    except Exception as e:
        return f"error: {e}"


def main():
    parser = argparse.ArgumentParser(description="Find local and public IP addresses for this device.")
    parser.add_argument("--public", action="store_true", help="Also fetch public/external IP")
    args = parser.parse_args()

    print("Hostname:", get_hostname())
    primary = get_primary_local_ip()
    print("Primary local IP (used for outbound):", primary)

    all_ips = get_all_local_ips()
    if all_ips:
        print("All local non-loopback IPs:")
        for ip in all_ips:
            print("  -", ip)
    else:
        print("All local non-loopback IPs: (none found via hostname lookup)")

    if args.public:
        print("Fetching public IP (may take a moment)...")
        pub = get_public_ip()
        print("Public IP:", pub)


if __name__ == "__main__":
    main()
