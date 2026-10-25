# backend/validator.py
import ipaddress, sys, os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from backend.config import LAB_SUBNET, LAB_HOSTS

def classify_target(ip: str) -> dict:
    try:
        addr = ipaddress.ip_address(ip.strip())
    except ValueError:
        return {"valid": False, "in_lab": False, "label": "Invalid",
                "message": f"'{ip}' is not a valid IP address"}
    in_lab = addr in LAB_SUBNET
    label  = LAB_HOSTS.get(ip, "Unknown host")
    return {
        "valid": True, "in_lab": in_lab,
        "label": label if in_lab else "External host",
        "message": (f"Lab target: {label}" if in_lab
                    else f"{ip} is outside 192.168.56.0/24 — supervisor confirmation required"),
    }