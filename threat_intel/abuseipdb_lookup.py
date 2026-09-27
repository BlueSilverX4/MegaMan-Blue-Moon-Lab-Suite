import os
import requests
import json

def check_abuseipdb(ip_address, api_key):
    url = 'https://api.abuseipdb.com/api/v2/check'
    querystring = {
        'ipAddress': ip_address,
        'maxAgeInDays': '90'
    }
    headers = {
        'Accept': 'application/json',
        'Key': api_key
    }
    
    response = requests.request(method='GET', url=url, headers=headers, params=querystring)
    if response.status_code == 200:
        data = response.json()['data']
        print(f"[+] IP: {data['ipAddress']}")
        print(f"    Abuse Confidence Score: {data['abuseConfidenceScore']}%")
        print(f"    ISP: {data['isp']}")
        print(f"    Total Reports: {data['totalReports']}")
        return data
    else:
        print(f"[-] Error querying AbuseIPDB: {response.status_code}")
        return None

if __name__ == "__main__":
    API_KEY = os.getenv("ABUSEIPDB_API_KEY", "YOUR_API_KEY_HERE")
    target_ip = input("Enter IP to check with AbuseIPDB: ")
    check_abuseipdb(target_ip, API_KEY)
