from router.router_scan import scan_router
from switch.switch_scan import scan_switch
from graph.network_graph import NetworkGraph
from database.queries import (
    create_device,
    save_scan_result,
    save_edge,
    save_metrics
)

def scan_network(devices):
    graph = NetworkGraph()
    device_id_map = {}

    # Scan & build graph
    for d in devices:
        ip = d["ip"]
        dtype = d["type"]

        graph.add_device(ip, dtype)

        if dtype == "router":
            result = scan_router(ip)
        else:
            result = scan_switch(ip)

        if not result:
            continue

        device_id = get_or_create_device(ip, dtype)
        device_id_map[ip] = device_id

        save_scan_result(device_id, result["ports"])

        for neighbor in result["neighbors"]:
            graph.add_connection(ip, neighbor)

    # Save edges
    for src, dst in graph.graph.edges():
        if src in device_id_map and dst in device_id_map:
            save_edge(device_id_map[src], device_id_map[dst])

    # Save graph metrics
    degree = graph.calculate_concentration()
    between = graph.calculate_critical_nodes()

    for ip in degree:
        if ip in device_id_map:
            save_metrics(
                device_id_map[ip],
                degree[ip],
                between.get(ip, 0.0)
            )

    return {"status": "scan_saved"}

