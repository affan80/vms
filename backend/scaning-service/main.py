from fastapi import FastAPI, HTTPException, Depends
from database.queries import create_user, get_user_by_email
from devices.add_device import router as add_device_router
from devices.list_device import router as list_device_router
from scanner.scan_manager import scan_device
from database.db import get_db
from auth.jwt import verify_jwt

app = FastAPI()
app.include_router(add_device_router)
app.include_router(list_device_router)

@app.post("/internal/signup")
def signup(data: dict):
    if not all(k in data for k in ("name", "email", "password_hash")):
        raise HTTPException(status_code=400, detail="Invalid payload")
    
    try:
        user = create_user(
            name=data["name"],
            email=data["email"],
            password_hash=data["password_hash"]
        )

        return {
            "id": user["id"],
            "email": user["email"]
        }

    except Exception as e:
        print("SIGNUP ERROR:", e)
        raise HTTPException(status_code=500, detail=str(e))

@app.post("/internal/get-user")
def get_user(data: dict):
    if "email" not in data:
        raise HTTPException(status_code=400, detail="Email required")

    user = get_user_by_email(data["email"])

    if not user:
        raise HTTPException(status_code=404, detail="User not found")

    return {
        "id": user["id"],
        "name": user["name"],
        "email": user["email"],
        "password_hash": user["password_hash"],
        "role": user["role"]
    }


@app.post("/scan")
def start_scan(data: dict, user=Depends(verify_jwt)):
    scan_id = scan_device(data["ip"], data["device_type"])
    return {"scan_id": scan_id}

@app.get("/scans")
def list_scans(user=Depends(verify_jwt)):
    conn = get_db()
    cur = conn.cursor()
    cur.execute("SELECT * FROM scans ORDER BY started_at DESC")
    rows = cur.fetchall()
    cur.close()
    conn.close()
    return rows

@app.get("/scan/{scan_id}")
def scan_details(scan_id: int, user=Depends(verify_jwt)):
    conn = get_db()
    cur = conn.cursor()
    cur.execute(
        "SELECT scan_type, result FROM scan_results WHERE scan_id=%s",
        (scan_id,)
    )
    results = cur.fetchall()
    cur.close()
    conn.close()
    return results
