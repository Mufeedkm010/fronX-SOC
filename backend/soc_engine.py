import sqlite3
import datetime
import subprocess


# ---------------------------------------------------
# Create Incident
# ---------------------------------------------------

def create_incident(ip, severity="High"):

    conn = sqlite3.connect("fronx.db")
    c = conn.cursor()

    c.execute("""
        INSERT INTO incidents (created_at, ip, severity, status, assigned_to, notes)
        VALUES (?, ?, ?, ?, ?, ?)
    """, (
        datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        ip,
        severity,
        "Open",
        "Unassigned",
        ""
    ))

    conn.commit()
    conn.close()


# ---------------------------------------------------
# IOC Check
# ---------------------------------------------------

def check_ioc(ip):

    conn = sqlite3.connect("fronx.db")
    c = conn.cursor()

    c.execute("SELECT ip FROM iocs WHERE ip = ?", (ip,))
    result = c.fetchone()

    conn.close()

    return result is not None


# ---------------------------------------------------
# Auto Block IP (SOAR Lite)
# ---------------------------------------------------

def auto_block(ip):

    try:
        subprocess.run(["iptables", "-A", "INPUT", "-s", ip, "-j", "DROP"])
        print(f"🔥 SOAR Auto-Blocked IP: {ip}")
    except Exception as e:
        print("Block failed:", e)


# ---------------------------------------------------
# Correlation Engine
# ---------------------------------------------------

def correlate_and_escalate(ip):

    conn = sqlite3.connect("fronx.db")
    c = conn.cursor()

    c.execute("""
        SELECT COUNT(*)
        FROM logs
        WHERE message LIKE ?
    """, (f"%{ip}%",))

    count = c.fetchone()[0]
    conn.close()

    if count >= 5:
        create_incident(ip, "Critical")
        auto_block(ip)
