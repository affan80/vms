from cve.cve_fetcher import fetch_cves

def map_cves_to_device(device):
    """
    Decide which services apply to device
    """

    services = []

    ports = device.get("ports", [])

    if 22 in ports:
        services.append("ssh")
    if 161 in ports:
        services.append("snmp")
    if 80 in ports or 443 in ports:
        services.append("http")

    cve_data = []

    for svc in services:
        cves = fetch_cves(svc)
        for c in cves:
            c["service"] = svc
            cve_data.append(c)

    return cve_data

