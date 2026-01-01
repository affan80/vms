from fastapi import APIRouter, Depends
from auth.jwt import verify_jwt

router = APIRouter()

@router.post("/devices")
def add_device(
    device: dict,
    user=Depends(verify_jwt)
):
    return {
        "message": "Device added",
        "added_by": user["user_id"]
    }

