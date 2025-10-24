# services.py
import os
import requests

# ENV variable names:
# VT_API_KEY, ABUSEIPDB_KEY, OTX_API_KEY

def query_virustotal(resource):
    """resource can be ip, domain or file hash - auto endpoint select"""
    key = os.getenv("VT_API_KEY")
    if not key:
        return {"available": False, "source": "VirusTotal", "error": "VT_API_KEY not set"}
    headers = {"x-apikey": key}
    # decide endpoint
    # try IP endpoint first, fallback to domain/hash
    endpoints = [
        f"https://www.virustotal.com/api/v3/ip_addresses/{resource}",
        f"https://www.virustotal.com/api/v3/domains/{resource}",
        f"https://www.virustotal.com/api/v3/files/{resource}"
    ]
    for url in endpoints:
        resp = requests.get(url, headers=headers, timeout=15)
        if resp.status_code == 200:
            data = resp.json()
            return {"available": True, "source": "VirusTotal", "data": data}
        # 404 means resource not present at that endpoint — try next
        if resp.status_code == 429:
            return {"available": False, "source": "VirusTotal", "error": "Rate limited"}
    return {"available": False, "source": "VirusTotal", "error": "Not found"}

def query_abuseipdb(ip):
    key = os.getenv("ABUSEIPDB_KEY")
    if not key:
        return {"available": False, "source": "AbuseIPDB", "error": "ABUSEIPDB_KEY not set"}
    url = "https://api.abuseipdb.com/api/v2/check"
    params = {"ipAddress": ip, "maxAgeInDays": 90}
    headers = {"Accept": "application/json", "Key": key}
    try:
        resp = requests.get(url, headers=headers, params=params, timeout=15)
        if resp.status_code == 200:
            return {"available": True, "source": "AbuseIPDB", "data": resp.json()}
        if resp.status_code == 429:
            return {"available": False, "source": "AbuseIPDB", "error": "Rate limited"}
    except Exception as e:
        return {"available": False, "source": "AbuseIPDB", "error": str(e)}
    return {"available": False, "source": "AbuseIPDB", "error": f"HTTP {resp.status_code}"}

def query_otx_ip(ip):
    key = os.getenv("OTX_API_KEY")
    if not key:
        return {"available": False, "source": "OTX", "error": "OTX_API_KEY not set"}
    url = f"https://otx.alienvault.com/api/v1/indicators/IPv4/{ip}/general"
    headers = {"X-OTX-API-KEY": key}
    try:
        resp = requests.get(url, headers=headers, timeout=15)
        if resp.status_code == 200:
            return {"available": True, "source": "OTX", "data": resp.json()}
        if resp.status_code == 404:
            return {"available": False, "source": "OTX", "error": "Not found"}
    except Exception as e:
        return {"available": False, "source": "OTX", "error": str(e)}
    return {"available": False, "source": "OTX", "error": f"HTTP {resp.status_code}"}

