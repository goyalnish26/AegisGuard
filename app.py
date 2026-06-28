import os
import uvicorn
import datetime
import queue
import asyncio
from contextlib import asynccontextmanager
from fastapi import FastAPI, HTTPException, BackgroundTasks, Depends, WebSocket, WebSocketDisconnect
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse
from fastapi.middleware.cors import CORSMiddleware
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from jose import JWTError, jwt
from pydantic import BaseModel

import aegis_db
from aegis_detector import AegisDetector
import simulate_attacks

# Lifespan Context Manager & Engine init
detector = AegisDetector()
ACTIVE_CONNECTIONS = []
alert_queue = queue.Queue()

def queue_alert_callback(alert_data):
    alert_queue.put(alert_data)

aegis_db.register_alert_callback(queue_alert_callback)

async def broadcast_alerts():
    try:
        while True:
            while not alert_queue.empty():
                alert_data = alert_queue.get()
                for ws in list(ACTIVE_CONNECTIONS):
                    try:
                        await ws.send_json(alert_data)
                    except Exception as e:
                        print(f"[!] WebSocket broadcast error: {e}")
            await asyncio.sleep(0.1)
    except asyncio.CancelledError:
        pass

@asynccontextmanager
async def lifespan(app: FastAPI):
    # Startup
    aegis_db.init_db()
    
    # Seed database if it is empty
    try:
        import seed_db
        seed_db.seed_database()
    except Exception as e:
        print(f"[!] Error seeding database: {e}")
        
    print("[*] Starting AegisGuard Detection Engine...")
    detector.start()
    
    # Start the WebSocket broadcast background task
    broadcast_task = asyncio.create_task(broadcast_alerts())
    yield
    # Shutdown
    print("[*] Stopping AegisGuard Detection Engine...")
    detector.stop()
    broadcast_task.cancel()

app = FastAPI(
    title="AegisGuard Mini-SIEM",
    description="A real-time log security analysis and monitoring system.",
    version="1.0.0",
    lifespan=lifespan
)

# CORS Middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=["https://goyalnish26.github.io", "http://localhost:8000", "http://127.0.0.1:8000", "http://localhost:5500", "http://127.0.0.1:5500"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# JWT Authentication Config
SECRET_KEY = "super-secret-key-for-aegisguard-mini-siem"
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 60

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/api/login", auto_error=False)

def create_access_token(data: dict):
    to_encode = data.copy()
    expire = datetime.datetime.utcnow() + datetime.timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt

def verify_token(token: str = Depends(oauth2_scheme)):
    if not token:
        raise HTTPException(status_code=401, detail="Not authenticated")
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        username: str = payload.get("sub")
        if username is None:
            raise HTTPException(status_code=401, detail="Could not validate credentials")
        return username
    except JWTError:
        raise HTTPException(status_code=401, detail="Could not validate credentials")

# API Schemas
class ResolveRequest(BaseModel):
    status: str  # 'Resolved' or 'Dismissed' or 'New'

class SimulateRequest(BaseModel):
    attack_type: str  # 'ssh_failed', 'ssh_success', 'brute_force', 'sqli', 'xss', 'dir_traversal', 'sensitive_path', 'normal'

# Endpoints
@app.post("/api/login")
def login(form_data: OAuth2PasswordRequestForm = Depends()):
    if form_data.username == "admin" and form_data.password == "aegisguard":
        access_token = create_access_token(data={"sub": form_data.username})
        return {"access_token": access_token, "token_type": "bearer"}
    raise HTTPException(status_code=400, detail="Incorrect username or password")

@app.get("/api/alerts")
def get_alerts(severity: str = None, status: str = None, limit: int = 100, offset: int = 0):
    try:
        alerts = aegis_db.get_alerts(limit=limit, offset=offset, status=status, severity=severity)
        return {"status": "success", "data": alerts}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.post("/api/alerts/{alert_id}/resolve")
def resolve_alert(alert_id: int, request: ResolveRequest, current_user: str = Depends(verify_token)):
    if request.status not in ["New", "Resolved", "Dismissed"]:
        raise HTTPException(status_code=400, detail="Invalid status. Must be New, Resolved, or Dismissed.")
    try:
        aegis_db.resolve_alert(alert_id, request.status)
        return {"status": "success", "message": f"Alert {alert_id} status updated to {request.status}."}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.post("/api/alerts/clear")
def clear_alerts(current_user: str = Depends(verify_token)):
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

# WebSocket Alert Stream
@app.websocket("/ws/alerts")
async def alert_stream(websocket: WebSocket):
    await websocket.accept()
    ACTIVE_CONNECTIONS.append(websocket)
    try:
        while True:
            # Keep client connection open, wait for heartbeat or close
            await websocket.receive_text()
    except WebSocketDisconnect:
        pass
    except Exception:
        pass
    finally:
        if websocket in ACTIVE_CONNECTIONS:
            ACTIVE_CONNECTIONS.remove(websocket)

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
docs_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), "docs")
if not os.path.exists(docs_dir):
    os.makedirs(docs_dir, exist_ok=True)

@app.get("/dashboard")
def read_dashboard():
    index_path = os.path.join(docs_dir, "index.html")
    if os.path.exists(index_path):
        return FileResponse(index_path)
    return {"status": "success", "message": "AegisGuard Dashboard not found."}

# Mount static files at root (/) after all API routes so relative URLs work in both environments
app.mount("/", StaticFiles(directory=docs_dir, html=True), name="docs")

if __name__ == "__main__":
    port = int(os.environ.get("PORT", 8000))
    uvicorn.run("app:app", host="0.0.0.0", port=port, reload=True)
