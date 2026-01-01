from fastapi import APIRouter, Depends
from auth.jwt import require_role

router = APIRouter()

@router.get("/devices")
def list_devices(
    admin=Depends(require_role("admin"))
):
    return {
        "devices": [],
        "access": "admin"
    }

