# ------------------ CVE & RISK ------------------
from reports.cve.divce_cve_mapper import map_cves_to_device
from reports.risk.risk_score import calculate_risk_score
from database.queries import save_cve_risk


def build_final_report(context):
    """
    Builds SOC / Dashboard ready report

    context comes from device_manager.process_device()
    """

    devices = context["devices"]
    graph = context["graph"].graph
    degree = context["degree"]
    betweenness = context["betweenness"]
    device_id_map = context["device_id_map"]

    cve_results = []
    device_risk_index = {}

    # CVE Mapping + Risk Calculation
    for device in devices:
        ip = device["ip"]

        cves = map_cves_to_device(device)

        device_total_risk = 0

        for cve in cves:
            risk = calculate_risk_score(
                cvss=cve["cvss"],
                degree=degree.get(ip, 0),
                betweenness=betweenness.get(ip, 0)
            )

            device_total_risk += risk

            # Persist CVE risk
            save_cve_risk(
                device_id_map[ip],
                cve["service"],
                cve["cve_id"],
                cve["cvss"],
                risk
            )

            cve_results.append({
                "ip": ip,
                "device_type": device["device_type"],
                "role": device["role"],
                "service": cve["service"],
                "cve_id": cve["cve_id"],
                "cvss": cve["cvss"],
                "risk_score": risk
            })

        device_risk_index[ip] = round(device_total_risk, 2)

    # Dashboard Summary
    critical_cves = [c for c in cve_results if c["risk_score"] >= 7]

    summary = {
        "total_devices": len(devices),
        "routers": len([d for d in devices if d["device_type"] == "router"]),
        "switches": len([d for d in devices if d["device_type"] == "switch"]),
        "critical_cves": len(critical_cves),
        "highest_risk_device": max(
            device_risk_index,
            key=device_risk_index.get
        ) if device_risk_index else None
    }

    # Topology for Dashboard
    topology = {
        "nodes": [
            {
                "id": d["ip"],
                "type": d["device_type"],
                "role": d["role"],
                "risk": device_risk_index.get(d["ip"], 0)
            }
            for d in devices
        ],
        "edges": list(graph.edges())
    }

    # Final Dashboard JSON
    return {
        "summary": summary,
        "topology": topology,
        "cve_risks": sorted(
            cve_results,
            key=lambda x: x["risk_score"],
            reverse=True
        )
    }

