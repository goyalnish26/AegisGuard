import os
import time
import random
import datetime

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
AUTH_LOG_PATH = os.path.join(BASE_DIR, "logs", "auth.log")
WEB_LOG_PATH = os.path.join(BASE_DIR, "logs", "web_access.log")

# Sample pools for simulation
MALICIOUS_IPS = ["198.51.100.42", "203.0.113.88", "185.220.101.5", "45.143.203.14", "91.241.19.84"]
NORMAL_IPS = ["192.168.1.15", "10.0.0.4", "192.168.1.105", "182.21.43.109", "122.160.231.10"]
USERNAMES = ["root", "admin", "ubuntu", "user", "oracle", "test", "support"]

def get_timestamp_logs():
    # Nginx style: [24/May/2026:14:15:00 +0530]
    now = datetime.datetime.now()
    nginx_ts = now.strftime("%d/%b/%Y:%H:%M:%S +0530")
    # SSH style: 2026-05-24T14:15:00+05:30
    ssh_ts = now.isoformat()
    return nginx_ts, ssh_ts

def write_log(filepath, content):
    os.makedirs(os.path.dirname(filepath), exist_ok=True)
    with open(filepath, "a") as f:
        f.write(content + "\n")
        f.flush()

def simulate_ssh_failed(ip=None, username=None):
    if not ip:
        ip = random.choice(MALICIOUS_IPS)
    if not username:
        username = random.choice(USERNAMES)
    _, ssh_ts = get_timestamp_logs()
    
    # 2026-05-24T14:15:00+05:30 [INFO] sshd[20412]: Failed password for root from 198.51.100.42 port 54312 ssh2
    log_line = f"{ssh_ts} [INFO] sshd[random.randint(10000, 30000)]: Failed password for {username} from {ip} port {random.randint(40000, 65000)} ssh2"
    write_log(AUTH_LOG_PATH, log_line)
    return f"Failed SSH attempt for {username} from {ip}"

def simulate_ssh_success(ip=None, username=None):
    if not ip:
        ip = random.choice(NORMAL_IPS)
    if not username:
        username = "ubuntu"
    _, ssh_ts = get_timestamp_logs()
    
    log_line = f"{ssh_ts} [INFO] sshd[20415]: Accepted password for {username} from {ip} port {random.randint(40000, 65000)} ssh2"
    write_log(AUTH_LOG_PATH, log_line)
    return f"Successful SSH login for {username} from {ip}"

def simulate_ssh_brute_force(ip=None):
    if not ip:
        ip = random.choice(MALICIOUS_IPS)
    target_user = random.choice(USERNAMES)
    
    results = []
    # Write 6 failed logins back-to-back
    for i in range(6):
        res = simulate_ssh_failed(ip, target_user)
        results.append(res)
        time.sleep(0.1) # Small gap
    return f"Brute Force attack simulated from {ip} (6 attempts)"

def simulate_sqli(ip=None):
    if not ip:
        ip = random.choice(MALICIOUS_IPS)
    nginx_ts, _ = get_timestamp_logs()
    
    sqli_payloads = [
        "GET /products.php?id=1%20UNION%20SELECT%20null,username,password%20FROM%20users HTTP/1.1",
        "GET /login.php?user=admin'%20OR%20'1'='1 HTTP/1.1",
        "POST /search.php?query=test'%20OR%201=1-- HTTP/1.1"
    ]
    payload = random.choice(sqli_payloads)
    log_line = f"{ip} - - [{nginx_ts}] \"{payload}\" 200 1204 \"-\" \"Mozilla/5.0\""
    write_log(WEB_LOG_PATH, log_line)
    return f"SQL Injection simulated from {ip}"

def simulate_xss(ip=None):
    if not ip:
        ip = random.choice(MALICIOUS_IPS)
    nginx_ts, _ = get_timestamp_logs()
    
    xss_payloads = [
        "GET /comment.php?msg=<script>alert('hack')</script> HTTP/1.1",
        "GET /profile?name=<svg/onload=alert(document.cookie)> HTTP/1.1",
        "POST /feedback?text=javascript:alert(1) HTTP/1.1"
    ]
    payload = random.choice(xss_payloads)
    log_line = f"{ip} - - [{nginx_ts}] \"{payload}\" 200 450 \"-\" \"Mozilla/5.0\""
    write_log(WEB_LOG_PATH, log_line)
    return f"XSS Attack simulated from {ip}"

def simulate_dir_traversal(ip=None):
    if not ip:
        ip = random.choice(MALICIOUS_IPS)
    nginx_ts, _ = get_timestamp_logs()
    
    payloads = [
        "GET /download.php?file=../../../../etc/passwd HTTP/1.1",
        "GET /view?path=..\\..\\..\\windows\\win.ini HTTP/1.1"
    ]
    payload = random.choice(payloads)
    log_line = f"{ip} - - [{nginx_ts}] \"{payload}\" 403 220 \"-\" \"Mozilla/5.0\""
    write_log(WEB_LOG_PATH, log_line)
    return f"Directory Traversal simulated from {ip}"

def simulate_sensitive_path(ip=None):
    if not ip:
        ip = random.choice(MALICIOUS_IPS)
    nginx_ts, _ = get_timestamp_logs()
    
    paths = ["/.env", "/wp-admin", "/config/db.php", "/phpinfo.php"]
    path = random.choice(paths)
    log_line = f"{ip} - - [{nginx_ts}] \"GET {path} HTTP/1.1\" 404 150 \"-\" \"Mozilla/5.0\""
    write_log(WEB_LOG_PATH, log_line)
    return f"Sensitive Path Scan simulated from {ip}"

def simulate_normal_traffic(ip=None):
    if not ip:
        ip = random.choice(NORMAL_IPS)
    nginx_ts, _ = get_timestamp_logs()
    
    pages = ["/home", "/about", "/contact", "/blog/post-12", "/static/images/logo.png", "/css/style.css"]
    page = random.choice(pages)
    log_line = f"{ip} - - [{nginx_ts}] \"GET {page} HTTP/1.1\" 200 2400 \"http://google.com\" \"Mozilla/5.0 (Windows NT 10.0; Win64; x64)\""
    write_log(WEB_LOG_PATH, log_line)
    return f"Normal web traffic from {ip}"

if __name__ == "__main__":
    print("[*] Running quick simulation run...")
    print(simulate_normal_traffic())
    time.sleep(0.5)
    print(simulate_ssh_failed())
    time.sleep(0.5)
    print(simulate_sqli())
    time.sleep(0.5)
    print(simulate_ssh_brute_force())
    print("[+] Logs generated. Check AegisGuard database alerts!")
