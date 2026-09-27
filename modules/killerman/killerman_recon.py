#!/usr/bin/env python3
"""
Blue Moon Lab Suite - KillerMan Recon Module
Identify & Reconnaissance (Nmap Discovery -> NumberMan SOAR Pipeline)
"""

import os
import sys
import json
import ipaddress
import subprocess
import nmap

# Path to NumberMan SOAR Script
NUMBERMAN_SCRIPT = os.path.abspath("threat_intel/numberman_soar.py")


def is_public_ip(ip_str):
    """Check if an IP address is a routable public IP (excluding private/loopback)."""
    try:
        ip_obj = ipaddress.ip_address(ip_str)
        return not (ip_obj.is_private or ip_obj.is_loopback or ip_obj.is_link_local or ip_obj.is_multicast)
    except ValueError:
        return False


def run_killerman_scan(target_subnet):
    print("=" * 60)
    print(f" [KillerMan.EXE] Initiating Network Recon on: {target_subnet}")
    print("=" * 60)

    nm = nmap.PortScanner()
    
    # Fast SYN Scan / Ping Scan on top ports
    print("[*] Executing Nmap discovery scan...")
    try:
        nm.scan(hosts=target_subnet, arguments="-F -T4 -sV")
    except Exception as e:
        print(f"[-] Nmap Scan Failed: {e}")
        return

    discovered_hosts = nm.all_hosts()
    print(f"[+] Scan Complete. Total hosts discovered: {len(discovered_hosts)}\n")

    external_ips = []

    for host in discovered_hosts:
        state = nm[host].state()
        print(f" -> Host: {host} [{state.upper()}]")

        # Map active TCP ports
        if 'tcp' in nm[host]:
            for port, port_data in nm[host]['tcp'].items():
                if port_data['state'] == 'open':
                    service = port_data.get('name', 'unknown')
                    version = port_data.get('product', '')
                    print(f"    └── Port {port}/tcp OPEN: {service} {version}")

        # Evaluate if the IP is public/external
        if is_public_ip(host):
            print(f"    [!] EXTERNAL IP DETECTED: {host}")
            external_ips.append(host)
        else:
            print(f"    [*] Private/Internal IP: {host} (Skipping SOAR auto-trigger)")

    # Pass discovered external IPs directly to NumberMan SOAR
    if external_ips:
        print("\n" + "=" * 60)
        print(f" [KillerMan -> NumberMan Pipeline] Passing {len(external_ips)} External IP(s)")
        print("=" * 60)

        for ext_ip in external_ips:
            print(f"\n[>>>] Triggering NumberMan SOAR Engine for: {ext_ip}")
            subprocess.run([sys.executable, NUMBERMAN_SCRIPT, ext_ip])
    else:
        print("\n[+] No external/public IPs detected in scan results.")


if __name__ == "__main__":
    if len(sys.argv) > 1:
        target = sys.argv[1]
    else:
        target = input("Enter Target IP or Subnet to scan (e.g., 8.8.8.0/24 or 1.1.1.1): ").strip()

    run_killerman_scan(target)
