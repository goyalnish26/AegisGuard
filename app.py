import os
import uvicorn
from contextlib import asynccontextmanager
from fastapi import FastAPI, HTTPException, BackgroundTasks
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse
from pydantic import BaseModel

import aegis_db
from aegis_detector import AegisDetector
import simulate_attacks

# Lifespan Context Manager
detector = AegisDetector()

@asynccontextmanager
async def lifespan(app: FastAPI):
    # Startup
    aegis_db.init_db()
    print("[*] Starting AegisGuard Detection Engine...")
    detector.start()
    yield
    # Shutdown
    print("[*] Stopping AegisGuard Detection Engine...")
    detector.stop()

app = FastAPI(
    title="AegisGuard Mini-SIEM",
    description="A real-time log security analysis and monitoring system.",
    version="1.0.0",
    lifespan=lifespan
)

# API Schemas
class ResolveRequest(BaseModel):
    status: str  # 'Resolved' or 'Dismissed' or 'New'

class SimulateRequest(BaseModel):
    attack_type: str  # 'ssh_failed', 'ssh_success', 'brute_force', 'sqli', 'xss', 'dir_traversal', 'sensitive_path', 'normal'

# Endpoints
@app.get("/api/alerts")
def get_alerts(severity: str = None, status: str = None, limit: int = 100, offset: int = 0):
    try:
        alerts = aegis_db.get_alerts(limit=limit, offset=offset, status=status, severity=severity)
        return {"status": "success", "data": alerts}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.post("/api/alerts/{alert_id}/resolve")
def resolve_alert(alert_id: int, request: ResolveRequest):
    if request.status not in ["New", "Resolved", "Dismissed"]:
        raise HTTPException(status_code=400, detail="Invalid status. Must be New, Resolved, or Dismissed.")
    try:
        aegis_db.resolve_alert(alert_id, request.status)
        return {"status": "success", "message": f"Alert {alert_id} status updated to {request.status}."}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.post("/api/alerts/clear")
def clear_alerts():
    try:
        aegis_db.clear_db()
        return {"status": "success", "message": "All database alerts cleared."}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.get("/api/stats")
def get_stats():
    try:
        stats = aegis_db.get_stats()
        return {"status": "success", "data": stats}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

def run_simulation(attack_type: str):
    try:
        if attack_type == "ssh_failed":
            simulate_attacks.simulate_ssh_failed()
        elif attack_type == "ssh_success":
            simulate_attacks.simulate_ssh_success()
        elif attack_type == "brute_force":
            simulate_attacks.simulate_ssh_brute_force()
        elif attack_type == "sqli":
            simulate_attacks.simulate_sqli()
        elif attack_type == "xss":
            simulate_attacks.simulate_xss()
        elif attack_type == "dir_traversal":
            simulate_attacks.simulate_dir_traversal()
        elif attack_type == "sensitive_path":
            simulate_attacks.simulate_sensitive_path()
        elif attack_type == "normal":
            # Simulate a few normal logs
            for _ in range(5):
                simulate_attacks.simulate_normal_traffic()
    except Exception as e:
        print(f"[!] Error in background simulation: {e}")

@app.post("/api/simulate")
def trigger_simulation(request: SimulateRequest, background_tasks: BackgroundTasks):
    valid_types = ["ssh_failed", "ssh_success", "brute_force", "sqli", "xss", "dir_traversal", "sensitive_path", "normal"]
    if request.attack_type not in valid_types:
        raise HTTPException(status_code=400, detail=f"Invalid attack_type. Must be one of: {', '.join(valid_types)}")
        
    background_tasks.add_task(run_simulation, request.attack_type)
    return {"status": "success", "message": f"Simulation of {request.attack_type} started in the background."}

# Mount static files (Frontend code)
static_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), "static")
if not os.path.exists(static_dir):
    os.makedirs(static_dir, exist_ok=True)

app.mount("/static", StaticFiles(directory=static_dir), name="static")

@app.get("/")
def read_root():
    index_path = os.path.join(static_dir, "index.html")
    if os.path.exists(index_path):
        return FileResponse(index_path)
    return {"status": "success", "message": "AegisGuard API is running. Dashboard is not yet created in /static."}

@app.get("/dashboard")
def read_dashboard():
    index_path = os.path.join(static_dir, "index.html")
    if os.path.exists(index_path):
        return FileResponse(index_path)
    return {"status": "success", "message": "AegisGuard API is running. Dashboard is not yet created in /static."}


if __name__ == "__main__":
    uvicorn.run("app:app", host="127.0.0.1", port=8000, reload=True)
