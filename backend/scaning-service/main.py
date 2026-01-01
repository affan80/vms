from fastapi import FastAPI, Depends
from typing import List, Dict
from scanner.scan_manage import run_scan
from devices.device_manager import process_device
from reports.report_manager import build_report
from auth.jwt import verify_token

app = FastAPI(
    title="Network Vulnerability Management Service",
    version="1.0.0"
)

# HEALTH CHECK
@app.get("/health")
def health():
    return {"status": "running"}


# -------------------------------------------------
# MAIN SCAN ENDPOINT
# -------------------------------------------------
@app.post("/scan")
def scan_network(
    devices: List[Dict],
    user=Depends(verify_token)  # remove if auth not needed
):
    """
    devices example:
    [
      {"ip": "192.168.1.1", "type": "router"},
      {"ip": "192.168.1.2", "type": "switch"}
    ]
    """
    return run_scan(devices)


# -------------------------------------------------
# OPTIONAL: DEBUG / DEV ENDPOINTS
# (useful during development)
# -------------------------------------------------

@app.post("/debug/process-devices")
def debug_process_devices(scan_results: List[Dict]):
    """
    Directly test device_manager
    """
    return process_device(scan_results)


@app.post("/debug/build-report")
def debug_build_report(context: Dict):
    """
    Directly test report_manager
    """
    return build_final_report(context)

