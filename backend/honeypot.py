import socket
import threading
import sqlite3
import datetime
from geo_tracker import get_ip_info
from soc_engine import create_incident, correlate_and_escalate, check_ioc

HONEYPOT_PORT = 2222

honeypot_running = False
server_socket = None


# ---------------------------------------------------
# Risk Scoring
# ---------------------------------------------------

def calculate_risk(ip):

    if ip.startswith("127.") or ip.startswith("192.168.") or ip.startswith("10."):
        return 40

    return 80


# ---------------------------------------------------
# Start Honeypot
# ---------------------------------------------------

def start_honeypot(socketio):

    global honeypot_running
    global server_socket

    if honeypot_running:
        print("⚠️ Honeypot already running")
        return

    try:
        server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        server_socket.bind(("0.0.0.0", HONEYPOT_PORT))
        server_socket.listen(5)

    except Exception as e:
        print("❌ Honeypot failed to bind:", e)
        honeypot_running = False
        return

    honeypot_running = True

    print(f"🐝 Honeypot listening on port {HONEYPOT_PORT}")


    def handle_client(client_socket, addr):

        ip = addr[0]
        print(f"🐝 Honeypot triggered by {ip}")

        geo_info = get_ip_info(ip)
        timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")

        risk_score = calculate_risk(ip)

        # IOC escalation
        if check_ioc(ip):
            risk_score = 100
            create_incident(ip, "Critical")

        message = f"Honeypot access attempt from {ip} | Risk:{risk_score}"

        # Store log
        conn = sqlite3.connect("fronx.db")
        c = conn.cursor()

        c.execute("""
            INSERT INTO logs (timestamp, message, threat_level, geo_info)
            VALUES (?, ?, ?, ?)
        """, (
            timestamp,
            message,
            "High",
            geo_info
        ))

        conn.commit()
        conn.close()

        # Correlation engine
        correlate_and_escalate(ip)

        # Emit to frontend
        socketio.emit("new_log", {
            "message": message,
            "threat": "High",
            "geo": geo_info
        })

        client_socket.close()


    def server_loop():

        global honeypot_running

        while honeypot_running:
            try:
                client_socket, addr = server_socket.accept()
                threading.Thread(
                    target=handle_client,
                    args=(client_socket, addr),
                    daemon=True
                ).start()
            except Exception:
                break

    threading.Thread(target=server_loop, daemon=True).start()


# ---------------------------------------------------
# Stop Honeypot
# ---------------------------------------------------

def stop_honeypot():

    global honeypot_running
    global server_socket

    honeypot_running = False

    if server_socket:
        try:
            server_socket.close()
            print("🛑 Honeypot stopped")
        except Exception:
            pass

    server_socket = None


# ---------------------------------------------------
# Status
# ---------------------------------------------------

def get_status():
    return honeypot_running
