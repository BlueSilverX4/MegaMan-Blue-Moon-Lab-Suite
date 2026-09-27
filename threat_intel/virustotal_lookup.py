import os
import requests

def check_virustotal(ip_address, api_key):
    url = f"https://www.virustotal.com/api/v3/ip_addresses/{ip_address}"
    headers = {
        "accept": "application/json",
        "x-apikey": api_key
    }
    
    response = requests.get(url, headers=headers)
    if response.status_code == 200:
        attributes = response.json()['data']['attributes']
        stats = attributes['last_analysis_stats']
        print(f"[+] VirusTotal Report for {ip_address}:")
        print(f"    Malicious: {stats['malicious']}")
        print(f"    Suspicious: {stats['suspicious']}")
        print(f"    Harmless: {stats['harmless']}")
        print(f"    Undetected: {stats['undetected']}")
        return stats
    else:
        print(f"[-] Error querying VirusTotal: {response.status_code}")
        return None

if __name__ == "__main__":
    API_KEY = os.getenv("VIRUSTOTAL_API_KEY", "YOUR_API_KEY_HERE")
    target_ip = input("Enter IP to check with VirusTotal: ")
    check_virustotal(target_ip, API_KEY)
