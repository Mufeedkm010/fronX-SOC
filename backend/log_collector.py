import subprocess
import sqlite3
import re
from threat_detector import detect_threat
from ai_engine import analyze_log
from geo_tracker import get_ip_info
from brute_engine import detect_bruteforce
from firewall import block_ip

def monitor_logs(socketio):

    process = subprocess.Popen(
        ["journalctl", "-u", "ssh", "-f", "--no-pager", "-o", "cat"],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        bufsize=1
    )

    for line in iter(process.stdout.readline, ''):

        if "Failed password" in line or "Invalid user" in line or "Accepted password" in line:

            print("Log detected:", line.strip())

            rule_threat = detect_threat(line)
            ai_threat = analyze_log(line)
            final_threat = "High" if ai_threat == "High" else rule_threat

            ip_match = re.search(r'\d+\.\d+\.\d+\.\d+', line)
            geo_info = "Local"

            if ip_match:
                ip = ip_match.group()
                geo_info = get_ip_info(ip)
                detect_bruteforce(ip)
                block_ip(ip)

            # Save to DB
            conn = sqlite3.connect("fronx.db")
            c = conn.cursor()
            c.execute("""
                INSERT INTO logs (timestamp, message, threat_level, geo_info)
                VALUES (datetime('now'), ?, ?, ?)
            """, (line.strip(), final_threat, geo_info))
            conn.commit()
            conn.close()

            # ✅ CORRECT EMIT (NO broadcast=True)
            socketio.emit("new_log", {
                "message": line.strip(),
                "threat": final_threat,
                "geo": geo_info
            })
