# 🛡️ AegisGuard - Mini-SIEM Security Platform

[![Python](https://img.shields.io/badge/Python-3.9+-3670A0?style=for-the-badge&logo=python&logoColor=ffdd54)](https://www.python.org/)
[![FastAPI](https://img.shields.io/badge/FastAPI-005571?style=for-the-badge&logo=fastapi)](https://fastapi.tiangolo.com/)
[![SQLite](https://img.shields.io/badge/SQLite-07405E?style=for-the-badge&logo=sqlite&logoColor=white)](https://sqlite.org/)
[![Status](https://img.shields.io/badge/Status-Active-brightgreen?style=for-the-badge)](#)

AegisGuard is a lightweight, real-time **Security Information and Event Management (SIEM)** and log security monitoring platform. It actively monitors authorization and web access logs, detects suspicious activities and signature-based attacks using a custom regex rules engine, and displays security alerts on an interactive dashboard.

---

## 🚀 Features

- **🔍 Real-Time Log Tailer & Parser**
  - Dynamically monitors auth logs (`auth.log`) and web access logs (`web_access.log`).
- **🛡️ Stateful & Stateless Threat Detection Engine**
  - Detects web-based attacks (SQL Injection, XSS, Path Traversal, Sensitive Directory discovery).
  - Implements **Stateful Analysis** to track and catch SSH Brute Force attacks (e.g., 5+ failed attempts from the same IP within a 60-second window).
- **📊 Interactive Web Dashboard**
  - Sleek modern UI displaying real-time alert statistics, severity breakdowns, threat timelines, and event logs.
  - Ability to review, resolve, or dismiss active security alerts.
- **⚡ Live Attack Simulator**
  - Integrated testing sandbox to simulate various web attacks and SSH login failures to verify detection logic on the fly.
- **🔔 Webhook Notifications**
  - Built-in webhook notifier to dispatch instant alerts to **Discord** or generic webhook receivers for **High** and **Critical** severity events.

---

## 📐 System Architecture

```
                      +-----------------------------+
                      | Logs (auth.log, web_access) |
                      +--------------+--------------+
                                     |
                                     v (Tail Engine)
                      +--------------+--------------+
                      |    AegisDetector Engine     | <--- reads rules.json
                      +--------------+--------------+
                                     |
                +--------------------+--------------------+
                |                                         |
                v                                         v
     +----------+----------+                   +----------+----------+
     |   SQLite Database   |                   |  Webhook Dispatcher |
     |      (aegis.db)     |                   |  (Discord/Slack)    |
     +----------+----------+                   +---------------------+
                |
                v
     +----------+----------+
     |    FastAPI Server   |
     +----------+----------+
                |
                v
     +----------+----------+
     |  Frontend Dashboard |
     +---------------------+
```

---

## 🛠️ Tech Stack

- **Backend:** FastAPI (Python 3.9+), Uvicorn, Pydantic
- **Database:** SQLite (Relational, self-contained)
- **Frontend:** Vanilla HTML5, CSS3 (Modern Glassmorphism & Cyberpunk layout), JavaScript
- **Log Processing:** Python threading & regex engine

---

## ⚙️ Setup & Installation

### 1. Clone the Repository
```bash
git clone https://github.com/goyalnish26/AegisGuard.git
cd AegisGuard
```

### 2. Install Dependencies
```bash
pip install -r requirements.txt
```

### 3. Setup Discord Alerts (Optional)
If you want to receive instant alerts on Discord, set the `AEGIS_WEBHOOK_URL` environment variable:

**Windows (PowerShell):**
```powershell
$env:AEGIS_WEBHOOK_URL="https://discord.com/api/webhooks/your-webhook-id/your-webhook-token"
```

**Linux / macOS:**
```bash
export AEGIS_WEBHOOK_URL="https://discord.com/api/webhooks/your-webhook-id/your-webhook-token"
```

### 4. Run the Application
Start the FastAPI server:
```bash
python app.py
```
By default, the server runs on `http://127.0.0.1:8000`.

Open your browser and navigate to:
- **SIEM Dashboard:** `http://127.0.0.1:8000/dashboard` (or `http://127.0.0.1:8000/`)
- **Interactive API Documentation (Swagger):** `http://127.0.0.1:8000/docs`

---

## 🧪 Simulation & Testing

AegisGuard comes with a built-in attack simulator (`simulate_attacks.py`) that generates mock log entries to test the detection engine. 

### Triggering Simulations
- **Via the Web Dashboard:** Click any of the simulation buttons (SQL Injection, SSH Brute Force, etc.) in the dashboard panel.
- **Via Command Line:** Run the simulator directly:
  ```bash
  python simulate_attacks.py
  ```
- **Via API Endpoint:** Post a request to `/api/simulate`:
  ```json
  // POST http://127.0.0.1:8000/api/simulate
  {
    "attack_type": "brute_force"
  }
  ```

---

## ✍️ Customizing Detection Rules

You can add, edit, or remove detection rules by modifying [rules.json](rules.json).

### Example: Custom SQL Injection Rule
```json
{
  "id": "RULE_SQL_INJECTION",
  "name": "SQL Injection Attempt",
  "log_type": "web",
  "severity": "Critical",
  "pattern": "(?i)(union\\s+select|select\\s+.*\\s+from|insert\\s+into|'\\s+or\\s+'\\d+'\\s*=\\s*'\\d+)",
  "description": "SQL injection signatures detected in the request URL or parameters.",
  "extract_fields": {
    "ip": 0
  }
}
```

> [!TIP]
> Use `is_stateful: true` for rules requiring threshold counts and time windows (like Brute-Force attack detection).

---

## 📡 API Endpoints Reference

| Method | Endpoint | Description |
| :--- | :--- | :--- |
| `GET` | `/api/alerts` | Fetch list of logs/alerts with optional severity/status filters. |
| `POST` | `/api/alerts/{id}/resolve` | Mark an alert status as `Resolved` or `Dismissed`. |
| `POST` | `/api/alerts/clear` | Purges all alerts from the database. |
| `GET` | `/api/stats` | Aggregated stats for the dashboard counters and charts. |
| `POST` | `/api/simulate` | Triggers a background attack log simulation. |

---

## 📜 License
This project is open-source and available under the [MIT License](LICENSE).
