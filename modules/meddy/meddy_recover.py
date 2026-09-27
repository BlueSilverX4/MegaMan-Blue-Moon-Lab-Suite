#!/usr/bin/env python3
"""
Blue Moon Lab Suite - Meddy Module
Recover & Remediation (Firewall Rollback & Container State Restoration)
"""

import sys
import subprocess
import docker
from datetime import datetime, timezone


def unblock_ip(ip_address):
    """Remove a specific IP drop rule from iptables."""
    print(f"[*] [Meddy.EXE] Reversing firewall block for IP: {ip_address}")
    try:
        check_cmd = ["sudo", "iptables", "-C", "INPUT", "-s", ip_address, "-j", "DROP"]
        check_res = subprocess.run(check_cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

        if check_res.returncode == 0:
            remove_cmd = ["sudo", "iptables", "-D", "INPUT", "-s", ip_address, "-j", "DROP"]
            res = subprocess.run(remove_cmd, capture_output=True, text=True)
            if res.returncode == 0:
                print(f"[+] [SUCCESS] Removed {ip_address} from iptables drop rules.")
                return True
            else:
                print(f"[-] Failed to unblock IP: {res.stderr}")
                return False
        else:
            print(f"[*] IP {ip_address} is not currently blocked in iptables.")
            return True
    except Exception as e:
        print(f"[-] Execution error: {e}")
        return False


def flush_all_suite_blocks():
    """Flush all custom INPUT rules applied during lab testing."""
    print("[*] [Meddy.EXE] Flushing all temporary laboratory firewall rules...")
    try:
        res = subprocess.run(["sudo", "iptables", "-F", "INPUT"], capture_output=True, text=True)
        if res.returncode == 0:
            print("[+] [SUCCESS] INPUT chain flushed successfully.")
        else:
            print(f"[-] Flush failed: {res.stderr}")
    except Exception as e:
        print(f"[-] Execution error: {e}")


def restore_container(container_name_or_id):
    """Restart and sanitize a target Docker container back to clean baseline state."""
    print(f"[*] [Meddy.EXE] Initiating clean state recovery for container: {container_name_or_id}")
    try:
        client = docker.from_env()
        container = client.containers.get(container_name_or_id)

        print(f"    └── Restarting {container.name} ({container.short_id})...")
        container.restart()
        
        # Verify post-recovery status
        container.reload()
        print(f"[+] [SUCCESS] Container {container.name} recovered. Current Status: {container.status.upper()}")
        return True
    except docker.errors.NotFound:
        print(f"[-] Error: Container '{container_name_or_id}' not found.")
        return False
    except Exception as e:
        print(f"[-] Recovery error: {e}")
        return False


def run_meddy_menu():
    print("=" * 60)
    print(f" [Meddy.EXE] Incident Recovery & Restoration Utility")
    print("=" * 60)
    print("1. Unblock Specific IP (iptables -D)")
    print("2. Flush All Laboratory Firewall Rules (iptables -F)")
    print("3. Restore/Restart Tainted Docker Container")
    print("4. Full Suite Recovery (Flush Blocks + Restart Target Container)")
    print("=" * 60)

    choice = input("Select Recovery Operation (1-4): ").strip()

    if choice == "1":
        target_ip = input("Enter IP Address to Unblock: ").strip()
        unblock_ip(target_ip)
    elif choice == "2":
        flush_all_suite_blocks()
    elif choice == "3":
        container_id = input("Enter Container Name or ID: ").strip()
        restore_container(container_id)
    elif choice == "4":
        container_id = input("Enter Container Name or ID to reset: ").strip()
        flush_all_suite_blocks()
        restore_container(container_id)
    else:
        print("[-] Invalid choice selection.")


if __name__ == "__main__":
    if len(sys.argv) > 1:
        flag = sys.argv[1]
        if flag == "--unblock" and len(sys.argv) > 2:
            unblock_ip(sys.argv[2])
        elif flag == "--reset-container" and len(sys.argv) > 2:
            restore_container(sys.argv[2])
        elif flag == "--flush":
            flush_all_suite_blocks()
        else:
            print("Usage: python3 meddy_recover.py [--unblock <IP> | --reset-container <NAME> | --flush]")
    else:
        run_meddy_menu()
