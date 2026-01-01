from scanner.router.nmap_scan import scan_router
from scanner.switch.switch_nmap_scan import scan_switch
from devices.device_manager import process_device
from reports.report_manager import build_final_report

def run_scan(devices):
    """
    Master scan function for Routers & Switches

    devices = [
        {"ip": "192.168.1.1", "type": "router"},
        {"ip": "192.168.1.2", "type": "switch"}
    ]
    """
    router_results = []
    switch_results = []

    # Separate devices by type
    routers = [d for d in devices if d.get("type") == "router"]
    switches = [d for d in devices if d.get("type") == "switch"]

    # Scan Routers
    for r in routers:
        ip = r.get("ip")
        if not ip:
            continue

        result = scan_router(ip)
        if result:
            router_results.append(result)

    # Scan Switches
    for s in switches:
        ip = s.get("ip")
        if not ip:
            continue

        result = scan_switch(ip)
        if result:
            switch_results.append(result)

    # Merge all scan results
    scanned_devices = router_results + switch_results

    if not scanned_devices:
        return {
            "error": "No devices scanned successfully"
        }

    # Device processing (graph + DB)
    device_context = process_device(scanned_devices)

    # Reporting (CVE + Risk + Dashboard)
    dashboard_json = build_report(device_context)

    return dashboard_json

