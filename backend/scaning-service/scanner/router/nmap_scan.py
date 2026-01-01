import nmap

def scan_router(ip):
    nm = nmap.PortScanner()
    nm.scan(ip, arguments="-sT -p 22,23,80,443")

    open_ports = []
    neighbors = []

    if ip not in nm.all_hosts():
        return None

    for proto in nm[ip].all_protocols():
        for port in nm[ip][proto]:
            open_ports.append(port)

            if port in [22, 80, 443]:
                neighbors.append(f"{ip}-mgmt")

    return {
        "ip": ip,
        "type": "router",
        "ports": open_ports,
        "neighbors": neighbors
    }

