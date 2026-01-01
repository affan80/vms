import nmap

def scan_switch(ip):
    """
    Switch Vulnerability Scanner
    -----------------------------
    Focus:
    - SNMP exposure
    - Management services
    - Infrastructure ports
    - Neighbor inference for graph building
    """

    nm = nmap.PortScanner()

    # Switch-focused ports
    # 22  -> SSH
    # 23  -> Telnet (critical)
    # 80  -> HTTP management
    # 443 -> HTTPS management
    # 161 -> SNMP (very critical)
    # 162 -> SNMP Trap
    ports = "22,23,80,443,161,162"

    try:
        nm.scan(
            hosts=ip,
            arguments=f"-sT -sU -sV -p {ports}"
        )
    except Exception as e:
        return None

    if ip not in nm.all_hosts():
        return None

    open_ports = []
    neighbors = []

    for proto in nm[ip].all_protocols():
        for port, data in nm[ip][proto].items():
            if data["state"] != "open":
                continue

            open_ports.append(port)

            service = data.get("name", "")

            # ---- Graph Neighbor Logic ----
            # SNMP usually means connection to NMS
            if port == 161 and service == "snmp":
                neighbors.append("snmp-manager")

            # Management interfaces imply admin workstation
            if port in (22, 80, 443):
                neighbors.append("admin-console")

            # Telnet is high-risk legacy access
            if port == 23:
                neighbors.append("legacy-admin")

    # Remove duplicate neighbors
    neighbors = list(set(neighbors))

    return {
        "ip": ip,
        "type": "switch",
        "ports": open_ports,
        "neighbors": neighbors,
        "risk_flags": {
            "snmp_exposed": 161 in open_ports,
            "telnet_enabled": 23 in open_ports,
            "insecure_http": 80 in open_ports and 443 not in open_ports
        }
    }

