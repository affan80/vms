from devices.graph.network_graph import NetworkGraph
from database.queries import (
    get_device,
    save_scan_result,
    save_edge,
    save_metrics
)

def classify_role(device):
    """
    Decide logical role based on scan data
    """
    ports = device.get("ports", [])
    dtype = device.get("device_type")

    if dtype == "router":
        return "gateway-router"

    if dtype == "switch":
        # SNMP usually indicates core / managed switch
        return "core-switch" if 161 in ports else "access-switch"

    return "unknown"


def process_device(scan_results):
    """
    Core asset intelligence layer

    Input:
        scan_results → output from router/switch scanners

    Output:
        context → used by report_manager
    """

    graph = NetworkGraph()
    device_id_map = {}

    # Normalize & Persist Devices
    for device in scan_results:
        ip = device["ip"]
        dtype = device["device_type"]

        # Assign logical role
        role = classify_role(device)
        device["role"] = role

        # Add node to graph
        graph.add_device(ip, dtype)

        # Save / get device from DB
        device_id = get_or_create_device(ip, dtype)
        device_id_map[ip] = device_id

        # Save scan result
        save_scan_result(device_id, device.get("ports", []))

    # Build Topology (Simple Model)
    # NOTE: Later replace with SNMP / ARP neighbors
    for src_ip in device_id_map:
        for dst_ip in device_id_map:
            if src_ip != dst_ip:
                graph.add_connection(src_ip, dst_ip)
                save_edge(
                    device_id_map[src_ip],
                    device_id_map[dst_ip]
                )

    # Graph Metrics
    degree = graph.calculate_concentration()
    betweenness = graph.calculate_critical_nodes()

    for ip in degree:
        save_metrics(
            device_id_map[ip],
            degree[ip],
            betweenness.get(ip, 0.0)
        )

    # Return Context
    return {
        "devices": scan_results,
        "graph": graph,
        "degree": degree,
        "betweenness": betweenness,
        "device_id_map": device_id_map
    }

