import requests

NVD_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
API_KEY = "PASTE_YOUR_API_KEY_HERE"

def fetch_cves(service, limit=5):
    headers = {
        "apiKey": API_KEY
    }

    params = {
        "keywordSearch": service,
        "resultsPerPage": limit
    }

    response = requests.get(
        NVD_URL,
        headers=headers,
        params=params,
        timeout=10
    )

    data = response.json()
    cves = []

    for item in data.get("vulnerabilities", []):
        cve = item["cve"]
        metrics = cve.get("metrics", {}).get("cvssMetricV31", [])

        cvss = metrics[0]["cvssData"]["baseScore"] if metrics else 5.0

        cves.append({
            "cve_id": cve["id"],
            "cvss": cvss
        })

    return cves

