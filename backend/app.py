import sqlite3
from flask import Flask, render_template, request, redirect, url_for, jsonify
from flask_socketio import SocketIO
from flask_login import login_user, login_required, logout_user, current_user
from flask import session
from datetime import datetime

from database import init_db
from auth import login_manager, User, users
from config import SECRET_KEY
from log_collector import monitor_logs
from honeypot import start_honeypot, stop_honeypot, get_status


# ---------------------------------------------------
# APP SETUP
# ---------------------------------------------------

app = Flask(
    __name__,
    template_folder="../frontend/templates",
    static_folder="../frontend/static"
)

app.config["SECRET_KEY"] = SECRET_KEY
socketio = SocketIO(app, async_mode="threading", cors_allowed_origins="*")

login_manager.init_app(app)
login_manager.login_view = "login"


# ---------------------------------------------------
# AUDIT LOGGER
# ---------------------------------------------------

def log_audit(action):
    conn = sqlite3.connect("fronx.db")
    c = conn.cursor()
    c.execute("""
        INSERT INTO audit_logs (timestamp, user, action)
        VALUES (datetime('now'), ?, ?)
    """, (current_user.id if current_user.is_authenticated else "system", action))
    conn.commit()
    conn.close()


# ---------------------------------------------------
# AUTH ROUTES
# ---------------------------------------------------

@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username = request.form.get("username")
        password = request.form.get("password")

        if username in users and users[username]["password"] == password:
            user = User(username, users[username]["role"])
            login_user(user)

            # Store last login time in session
            session["last_login"] = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

            log_audit(f"User {username} logged in")
            return redirect(url_for("overview"))

    return render_template("login.html")



@app.route("/logout")
@login_required
def logout():
    log_audit(f"User {current_user.id} logged out")
    logout_user()
    return redirect("/login")


# ---------------------------------------------------
# PAGE ROUTES
# ---------------------------------------------------

@app.route("/")
@login_required
def overview():
    return render_template("overview.html")


@app.route("/analytics")
@login_required
def analytics():
    return render_template("analytics.html")


@app.route("/map")
@login_required
def map_page():
    return render_template("map.html")

@app.route("/mitre")
@login_required
def mitre_page():
    return render_template("mitre.html")

@app.route("/threat-intel")
@login_required
def threat_intel_page():
    return render_template("threat_intel.html")

@app.route("/honeypot")
@login_required
def honeypot_page():
    return render_template("honeypot.html")


@app.route("/incidents")
@login_required
def incidents_page():
    return render_template("incidents.html")


@app.route("/ioc")
@login_required
def ioc_page():
    return render_template("ioc.html")


@app.route("/cases")
@login_required
def cases_page():
    return render_template("cases.html")


@app.route("/reports")
@login_required
def reports_page():
    return render_template("reports.html")


@app.route("/settings")
@login_required
def settings_page():
    return render_template("settings.html")


@app.route("/audit")
@login_required
def audit_page():
    return render_template("audit.html")


@app.route("/system-health")
@login_required
def system_health_page():
    return render_template("system_health.html")


# ---------------------------------------------------
# LOG API
# ---------------------------------------------------

@app.route("/api/logs")
@login_required
def get_logs():
    conn = sqlite3.connect("fronx.db")
    c = conn.cursor()
    c.execute("""
        SELECT timestamp, message, threat_level, geo_info
        FROM logs
        ORDER BY id DESC
        LIMIT 200
    """)
    logs = c.fetchall()
    conn.close()
    return jsonify(logs)


@app.route("/clear_logs", methods=["POST"])
@login_required
def clear_logs():
    if current_user.role != "admin":
        return jsonify({"error": "Unauthorized"}), 403

    conn = sqlite3.connect("fronx.db")
    c = conn.cursor()
    c.execute("DELETE FROM logs")
    conn.commit()
    conn.close()

    socketio.emit("clear_dashboard")
    log_audit("Logs cleared")

    return jsonify({"status": "cleared"})


# ---------------------------------------------------
# INCIDENT API
# ---------------------------------------------------

@app.route("/api/incidents")
@login_required
def get_incidents():
    conn = sqlite3.connect("fronx.db")
    c = conn.cursor()
    c.execute("SELECT * FROM incidents ORDER BY id DESC")
    data = c.fetchall()
    conn.close()
    return jsonify(data)

# ---------------------------------------------------
# INCIDENTS WITH AI SCORE + MITRE
# ---------------------------------------------------

@app.route("/api/incidents_with_score")
@login_required
def incidents_with_score():

    conn = sqlite3.connect("fronx.db")
    c = conn.cursor()

    # Get all incidents
    c.execute("SELECT * FROM incidents")
    incidents = c.fetchall()

    result = []

    for inc in incidents:

        incident_id = inc[0]
        ip = inc[2]
        severity = inc[3]

        # Severity scoring
        severity_score = 0
        if severity == "Critical":
            severity_score = 5
        elif severity == "High":
            severity_score = 3
        elif severity == "Medium":
            severity_score = 2
        else:
            severity_score = 1

        # Incident count
        c.execute("SELECT COUNT(*) FROM incidents WHERE ip=?", (ip,))
        incident_count = c.fetchone()[0]

        ai_score = (incident_count * 2) + severity_score

        # MITRE weights
        c.execute("""
            SELECT m.severity_weight
            FROM incident_mitre im
            JOIN mitre_techniques m
            ON im.technique_id = m.technique_id
            WHERE im.incident_id = ?
        """, (incident_id,))

        mitre_weights = c.fetchall()

        for w in mitre_weights:
            ai_score += w[0]

        # Risk classification
        if ai_score >= 15:
            risk = "Critical"
        elif ai_score >= 8:
            risk = "High"
        elif ai_score >= 3:
            risk = "Medium"
        else:
            risk = "Low"

        # Get MITRE techniques
        c.execute("""
            SELECT technique_id
            FROM incident_mitre
            WHERE incident_id = ?
        """, (incident_id,))
        techniques = [t[0] for t in c.fetchall()]

        result.append({
            "id": incident_id,
            "ip": ip,
            "severity": severity,
            "status": inc[4],
            "ai_score": ai_score,
            "risk": risk,
            "mitre": techniques
        })

    conn.close()
    return jsonify(result)

# ---------------------------------------------------
# CLEAR MITRE MAPPINGS (ADMIN ONLY)
# ---------------------------------------------------

@app.route("/admin/clear_mitre", methods=["POST"])
@login_required
def clear_mitre():

    if not current_user.is_admin():
        return jsonify({"error": "Unauthorized"}), 403

    conn = sqlite3.connect("fronx.db")
    c = conn.cursor()

    c.execute("DELETE FROM incident_mitre")

    conn.commit()
    conn.close()

    log_audit("Admin cleared all MITRE mappings")

    return jsonify({"status": "MITRE mappings cleared"})

# ---------------------------------------------------
# RESOLVE INCIDENT
# ---------------------------------------------------

@app.route("/incident/resolve/<int:incident_id>", methods=["POST"])
@login_required
def resolve_incident(incident_id):

    conn = sqlite3.connect("fronx.db")
    c = conn.cursor()

    c.execute("""
        UPDATE incidents
        SET status = 'Resolved'
        WHERE id = ?
    """, (incident_id,))

    conn.commit()
    conn.close()

    log_audit(f"Incident {incident_id} resolved")

    return jsonify({"status": "resolved"})


# ---------------------------------------------------
# IOC API
# ---------------------------------------------------

@app.route("/api/iocs")
@login_required
def get_iocs():
    conn = sqlite3.connect("fronx.db")
    c = conn.cursor()
    c.execute("SELECT * FROM iocs")
    data = c.fetchall()
    conn.close()
    return jsonify(data)

@app.route("/ioc/edit/<int:ioc_id>", methods=["POST"])
@login_required
def edit_ioc(ioc_id):

    if current_user.role != "admin":
        return jsonify({"error": "Unauthorized"}), 403

    data = request.json
    new_ip = data.get("ip")

    conn = sqlite3.connect("fronx.db")
    c = conn.cursor()

    c.execute("UPDATE iocs SET ip=? WHERE id=?", (new_ip, ioc_id))

    conn.commit()
    conn.close()

    log_audit(f"IOC {ioc_id} edited to {new_ip}")

    return jsonify({"status": "updated"})

@app.route("/ioc/resolve/<int:ioc_id>", methods=["POST"])
@login_required
def resolve_ioc(ioc_id):

    if current_user.role != "admin":
        return jsonify({"error": "Unauthorized"}), 403

    conn = sqlite3.connect("fronx.db")
    c = conn.cursor()

    c.execute("UPDATE iocs SET status='Resolved' WHERE id=?", (ioc_id,))

    conn.commit()
    conn.close()

    log_audit(f"IOC {ioc_id} resolved")

    return jsonify({"status": "resolved"})

@app.route("/ioc/delete/<int:ioc_id>", methods=["POST"])
@login_required
def delete_ioc(ioc_id):

    if current_user.role != "admin":
        return jsonify({"error": "Unauthorized"}), 403

    conn = sqlite3.connect("fronx.db")
    c = conn.cursor()

    c.execute("DELETE FROM iocs WHERE id=?", (ioc_id,))

    conn.commit()
    conn.close()

    log_audit(f"IOC {ioc_id} deleted")

    return jsonify({"status": "deleted"})

@app.route("/clear_iocs", methods=["POST"])
@login_required
def clear_iocs():

    if current_user.role != "admin":
        return jsonify({"error": "Unauthorized"}), 403

    conn = sqlite3.connect("fronx.db")
    c = conn.cursor()

    # Delete all IOC records
    c.execute("DELETE FROM iocs")

    # Reset AUTOINCREMENT counter
    c.execute("DELETE FROM sqlite_sequence WHERE name='iocs'")

    conn.commit()
    conn.close()

    log_audit("All IOCs cleared and ID reset")

    return jsonify({"status": "all_cleared"})


# ---------------------------------------------------
# ADD TO IOC (FROM THREAT INTEL)
# ---------------------------------------------------

@app.route("/api/add_to_ioc/<path:ip>", methods=["POST"])
@login_required
def add_to_ioc(ip):

    if current_user.role != "admin":
        return jsonify({"error": "Unauthorized"}), 403

    conn = sqlite3.connect("fronx.db")
    c = conn.cursor()

    try:
        c.execute("INSERT INTO iocs (ip) VALUES (?)", (ip,))
        conn.commit()
    except sqlite3.IntegrityError:
        conn.close()
        return jsonify({"error": "Already exists"}), 400

    conn.close()

    log_audit(f"{ip} added to IOC from Threat Intel")

    return jsonify({"status": "added"})

# ---------------------------------------------------
# ADD IOC
# ---------------------------------------------------

@app.route("/ioc/add", methods=["POST"])
@login_required
def add_ioc():

    data = request.json
    ip = data.get("ip")

    if not ip:
        return jsonify({"error": "IP required"}), 400

    conn = sqlite3.connect("fronx.db")
    c = conn.cursor()

    try:
        c.execute("""
            INSERT INTO iocs (ip)
            VALUES (?)
        """, (ip,))
        conn.commit()
    except sqlite3.IntegrityError:
        return jsonify({"error": "IOC already exists"}), 400

    conn.close()

    log_audit(f"IOC added: {ip}")

    return jsonify({"status": "ioc_added"})

# ---------------------------------------------------
# REPORTS API
# ---------------------------------------------------

@app.route("/api/report_data")
@login_required
def report_data():

    start_date = request.args.get("start")
    end_date = request.args.get("end")

    conn = sqlite3.connect("fronx.db")
    c = conn.cursor()

    # --------------------------
    # BUILD SAFE QUERY
    # --------------------------

    if start_date and end_date:

        c.execute("SELECT COUNT(*) FROM logs WHERE date(timestamp) BETWEEN ? AND ?", (start_date, end_date))
        total_logs = c.fetchone()[0]

        c.execute("""
            SELECT COUNT(*) FROM logs 
            WHERE date(timestamp) BETWEEN ? AND ? 
            AND threat_level='High'
        """, (start_date, end_date))
        high_alerts = c.fetchone()[0]

        c.execute("SELECT COUNT(*) FROM incidents WHERE date(created_at) BETWEEN ? AND ?", (start_date, end_date))
        total_incidents = c.fetchone()[0]

        c.execute("""
            SELECT COUNT(*) FROM incidents 
            WHERE date(created_at) BETWEEN ? AND ? 
            AND status='Open'
        """, (start_date, end_date))
        open_incidents = c.fetchone()[0]

        c.execute("""
            SELECT severity, COUNT(*) 
            FROM incidents 
            WHERE date(created_at) BETWEEN ? AND ? 
            GROUP BY severity
        """, (start_date, end_date))
        severity_data = c.fetchall()

    else:

        c.execute("SELECT COUNT(*) FROM logs")
        total_logs = c.fetchone()[0]

        c.execute("SELECT COUNT(*) FROM logs WHERE threat_level='High'")
        high_alerts = c.fetchone()[0]

        c.execute("SELECT COUNT(*) FROM incidents")
        total_incidents = c.fetchone()[0]

        c.execute("SELECT COUNT(*) FROM incidents WHERE status='Open'")
        open_incidents = c.fetchone()[0]

        c.execute("SELECT severity, COUNT(*) FROM incidents GROUP BY severity")
        severity_data = c.fetchall()

    # Monthly trend
    c.execute("""
        SELECT strftime('%Y-%m', created_at), COUNT(*)
        FROM incidents
        GROUP BY strftime('%Y-%m', created_at)
        ORDER BY created_at ASC
    """)
    monthly_trend = c.fetchall()

    conn.close()

    return jsonify({
        "total_logs": total_logs,
        "high_alerts": high_alerts,
        "total_incidents": total_incidents,
        "open_incidents": open_incidents,
        "severity_distribution": severity_data,
        "monthly_trend": monthly_trend
    })

# ---------------------------------------------------
# CLEAR INCIDENTS (Admin Only)
# ---------------------------------------------------

@app.route("/clear_incidents", methods=["POST"])
@login_required
def clear_incidents():

    if current_user.role != "admin":
        return jsonify({"error": "Unauthorized"}), 403

    conn = sqlite3.connect("fronx.db")
    c = conn.cursor()

    c.execute("DELETE FROM incidents")

    conn.commit()
    conn.close()

    log_audit("All incidents cleared")

    return jsonify({"status": "incidents_cleared"})

# ---------------------------------------------------
# SETTINGS API
# ---------------------------------------------------

@app.route("/api/settings")
@login_required
def get_settings():
    conn = sqlite3.connect("fronx.db")
    c = conn.cursor()
    c.execute("SELECT ai_sensitivity, log_retention_days, honeypot_autostart FROM settings WHERE id=1")
    data = c.fetchone()
    conn.close()

    return jsonify({
        "ai_sensitivity": data[0],
        "log_retention_days": data[1],
        "honeypot_autostart": data[2]
    })


@app.route("/settings/update", methods=["POST"])
@login_required
def update_settings():

    if current_user.role != "admin":
        return jsonify({"error": "Unauthorized"}), 403

    data = request.json

    conn = sqlite3.connect("fronx.db")
    c = conn.cursor()

    c.execute("""
        UPDATE settings
        SET ai_sensitivity=?,
            log_retention_days=?,
            honeypot_autostart=?
        WHERE id=1
    """,(data["ai_sensitivity"],
         data["log_retention_days"],
         data["honeypot_autostart"]))

    conn.commit()
    conn.close()

    # 🔥 Auto start/stop honeypot
    if data["honeypot_autostart"] == 1:
        start_honeypot(socketio)
    else:
        stop_honeypot()

    log_audit("Settings updated and honeypot synced")

    return jsonify({"status":"updated"})

@app.route("/settings/reset", methods=["POST"])
@login_required
def reset_settings():

    if current_user.role != "admin":
        return jsonify({"error": "Unauthorized"}), 403

    conn = sqlite3.connect("fronx.db")
    c = conn.cursor()

    c.execute("""
        UPDATE settings
        SET ai_sensitivity=5,
            log_retention_days=30,
            honeypot_autostart=0
        WHERE id=1
    """)

    conn.commit()
    conn.close()

    log_audit("Settings reset to default")

    return jsonify({"status": "reset"})

@app.route("/settings/apply_retention", methods=["POST"])
@login_required
def apply_retention():

    if current_user.role != "admin":
        return jsonify({"error": "Unauthorized"}), 403

    conn = sqlite3.connect("fronx.db")
    c = conn.cursor()

    c.execute("SELECT log_retention_days FROM settings WHERE id=1")
    retention_days = c.fetchone()[0]

    c.execute("""
        DELETE FROM logs
        WHERE date(timestamp) < date('now', ?)
    """,(f"-{retention_days} days",))

    conn.commit()
    conn.close()

    log_audit("Log retention cleanup executed")

    return jsonify({"status": "cleaned"})

@app.route("/settings/backup")
@login_required
def backup_db():

    if current_user.role != "admin":
        return jsonify({"error": "Unauthorized"}), 403

    from flask import send_file
    import shutil

    backup_path = "fronx_backup.db"
    shutil.copy("fronx.db", backup_path)

    log_audit("Database backup created")

    return send_file(backup_path, as_attachment=True)

# ---------------------------------------------------
# HONEYPOT LOG API
# ---------------------------------------------------

@app.route("/api/honeypot_logs")
@login_required
def get_honeypot_logs():

    conn = sqlite3.connect("fronx.db")
    c = conn.cursor()

    c.execute("""
        SELECT timestamp, message, threat_level, geo_info
        FROM logs
        WHERE message LIKE '%Honeypot%'
        ORDER BY id DESC
        LIMIT 200
    """)

    logs = c.fetchall()
    conn.close()

    return jsonify(logs)

@app.route("/clear_honeypot_logs", methods=["POST"])
@login_required
def clear_honeypot_logs():

    if current_user.role != "admin":
        return jsonify({"error": "Unauthorized"}), 403

    conn = sqlite3.connect("fronx.db")
    c = conn.cursor()

    c.execute("""
        DELETE FROM logs
        WHERE message LIKE '%Honeypot%'
    """)

    conn.commit()
    conn.close()

    log_audit("Honeypot logs cleared")

    return jsonify({"status": "honeypot_cleared"})



# ---------------------------------------------------
# HONEYPOT CONTROL
# ---------------------------------------------------

@app.route("/honeypot/start", methods=["POST"])
@login_required
def start_honeypot_route():
    if current_user.role != "admin":
        return jsonify({"error": "Unauthorized"}), 403

    start_honeypot(socketio)
    socketio.emit("honeypot_status", {"status": "running"})
    log_audit("Honeypot started")
    return jsonify({"status": "running"})


@app.route("/honeypot/stop", methods=["POST"])
@login_required
def stop_honeypot_route():
    if current_user.role != "admin":
        return jsonify({"error": "Unauthorized"}), 403

    stop_honeypot()
    socketio.emit("honeypot_status", {"status": "stopped"})
    log_audit("Honeypot stopped")
    return jsonify({"status": "stopped"})


@app.route("/honeypot/status")
@login_required
def honeypot_status():
    status = "running" if get_status() else "stopped"
    return jsonify({"status": status})

# ---------------------------------------------------
# SOC METRICS
# ---------------------------------------------------

@app.route("/api/soc_metrics")
@login_required
def soc_metrics():

    conn = sqlite3.connect("fronx.db")
    c = conn.cursor()

    # Open incidents
    c.execute("SELECT COUNT(*) FROM incidents WHERE status='Open'")
    open_incidents = c.fetchone()[0]

    # High alerts from logs
    c.execute("SELECT COUNT(*) FROM logs WHERE threat_level='High'")
    high_alerts = c.fetchone()[0]

    conn.close()

    return jsonify({
        "open_incidents": open_incidents,
        "high_alerts": high_alerts
    })

# ---------------------------------------------------
# AUDIT LOG API
# ---------------------------------------------------

@app.route("/api/audit")
@login_required
def get_audit_logs():

    conn = sqlite3.connect("fronx.db")
    c = conn.cursor()

    c.execute("""
        SELECT id, timestamp, user, action
        FROM audit_logs
        ORDER BY id DESC
        LIMIT 200
    """)

    data = c.fetchall()
    conn.close()

    return jsonify(data)

@app.route("/clear_audit", methods=["POST"])
@login_required
def clear_audit():

    if current_user.role != "admin":
        return jsonify({"error": "Unauthorized"}), 403

    conn = sqlite3.connect("fronx.db")
    c = conn.cursor()
    c.execute("DELETE FROM audit_logs")
    conn.commit()
    conn.close()

    log_audit("Audit logs cleared")

    return jsonify({"status": "cleared"})
# ---------------------------------------------------
# CASE API
# ---------------------------------------------------

@app.route("/api/cases")
@login_required
def get_cases():
    conn = sqlite3.connect("fronx.db")
    c = conn.cursor()
    c.execute("SELECT * FROM cases ORDER BY id DESC")
    data = c.fetchall()
    conn.close()
    return jsonify(data)


@app.route("/case/create", methods=["POST"])
@login_required
def create_case():
    data = request.json
    title = data.get("title")

    if not title:
        return jsonify({"error": "Title required"}), 400

    conn = sqlite3.connect("fronx.db")
    c = conn.cursor()

    c.execute("""
        INSERT INTO cases (created_at, title, status, assigned_to)
        VALUES (datetime('now'), ?, 'Open', ?)
    """, (title, current_user.id))

    conn.commit()
    conn.close()

    log_audit(f"Case created: {title}")

    return jsonify({"status": "case_created"})


# ---------------------------------------------------
# UPDATE CASE STATUS
# ---------------------------------------------------

@app.route("/case/update_status/<int:case_id>", methods=["POST"])
@login_required
def update_case_status(case_id):
    data = request.json
    status = data.get("status")

    conn = sqlite3.connect("fronx.db")
    c = conn.cursor()

    c.execute("UPDATE cases SET status=? WHERE id=?", (status, case_id))

    c.execute("""
        INSERT INTO case_timeline (case_id, action, timestamp, performed_by)
        VALUES (?, ?, datetime('now'), ?)
    """, (case_id, f"Status changed to {status}", current_user.id))

    conn.commit()
    conn.close()

    log_audit(f"Case {case_id} status changed to {status}")

    return jsonify({"status": "updated"})


# ---------------------------------------------------
# ASSIGN ANALYST
# ---------------------------------------------------

@app.route("/case/assign/<int:case_id>", methods=["POST"])
@login_required
def assign_case(case_id):
    data = request.json
    analyst = data.get("analyst")

    conn = sqlite3.connect("fronx.db")
    c = conn.cursor()

    c.execute("UPDATE cases SET assigned_to=? WHERE id=?", (analyst, case_id))

    c.execute("""
        INSERT INTO case_timeline (case_id, action, timestamp, performed_by)
        VALUES (?, ?, datetime('now'), ?)
    """, (case_id, f"Assigned to {analyst}", current_user.id))

    conn.commit()
    conn.close()

    log_audit(f"Case {case_id} assigned to {analyst}")

    return jsonify({"status": "assigned"})


# ---------------------------------------------------
# ADD NOTE
# ---------------------------------------------------

@app.route("/case/add_note/<int:case_id>", methods=["POST"])
@login_required
def add_case_note(case_id):
    data = request.json
    note = data.get("note")

    if not note:
        return jsonify({"error": "Note required"}), 400

    conn = sqlite3.connect("fronx.db")
    c = conn.cursor()

    c.execute("""
        INSERT INTO case_notes (case_id, note, created_at, created_by)
        VALUES (?, ?, datetime('now'), ?)
    """, (case_id, note, current_user.id))

    c.execute("""
        INSERT INTO case_timeline (case_id, action, timestamp, performed_by)
        VALUES (?, 'Note added', datetime('now'), ?)
    """, (case_id, current_user.id))

    conn.commit()
    conn.close()

    log_audit(f"Note added to case {case_id}")

    return jsonify({"status": "note_added"})


# ---------------------------------------------------
# GET CASE NOTES
# ---------------------------------------------------

@app.route("/api/case_notes/<int:case_id>")
@login_required
def get_case_notes(case_id):
    conn = sqlite3.connect("fronx.db")
    c = conn.cursor()

    c.execute("""
        SELECT note, created_at, created_by
        FROM case_notes
        WHERE case_id=?
        ORDER BY id DESC
    """, (case_id,))

    data = c.fetchall()
    conn.close()

    return jsonify(data)


# ---------------------------------------------------
# LINK INCIDENT
# ---------------------------------------------------

@app.route("/case/link_incident", methods=["POST"])
@login_required
def link_incident():
    data = request.json
    case_id = data.get("case_id")
    incident_id = data.get("incident_id")

    conn = sqlite3.connect("fronx.db")
    c = conn.cursor()

    c.execute("""
        INSERT INTO case_incidents (case_id, incident_id)
        VALUES (?, ?)
    """, (case_id, incident_id))

    c.execute("""
        INSERT INTO case_timeline (case_id, action, timestamp, performed_by)
        VALUES (?, ?, datetime('now'), ?)
    """, (case_id, f"Incident {incident_id} linked", current_user.id))

    conn.commit()
    conn.close()

    log_audit(f"Incident {incident_id} linked to case {case_id}")

    return jsonify({"status": "linked"})


# ---------------------------------------------------
# GET LINKED INCIDENTS
# ---------------------------------------------------

@app.route("/api/case_incidents/<int:case_id>")
@login_required
def get_case_incidents(case_id):
    conn = sqlite3.connect("fronx.db")
    c = conn.cursor()

    c.execute("""
        SELECT incidents.*
        FROM incidents
        JOIN case_incidents
        ON incidents.id = case_incidents.incident_id
        WHERE case_incidents.case_id=?
    """, (case_id,))

    data = c.fetchall()
    conn.close()

    return jsonify(data)


# ---------------------------------------------------
# GET CASE TIMELINE
# ---------------------------------------------------

@app.route("/api/case_timeline/<int:case_id>")
@login_required
def get_case_timeline(case_id):
    conn = sqlite3.connect("fronx.db")
    c = conn.cursor()

    c.execute("""
        SELECT action, timestamp, performed_by
        FROM case_timeline
        WHERE case_id=?
        ORDER BY id DESC
    """, (case_id,))

    data = c.fetchall()
    conn.close()

    return jsonify(data)

# ---------------------------------------------------
# RESOLVE CASE
# ---------------------------------------------------

@app.route("/case/resolve/<int:case_id>", methods=["POST"])
@login_required
def resolve_case(case_id):

    conn = sqlite3.connect("fronx.db")
    c = conn.cursor()

    c.execute("""
        UPDATE cases
        SET status='Closed'
        WHERE id=?
    """, (case_id,))

    # Optional: add timeline
    c.execute("""
        INSERT INTO case_timeline (case_id, action, timestamp, performed_by)
        VALUES (?, 'Case resolved', datetime('now'), ?)
    """, (case_id, current_user.id))

    conn.commit()
    conn.close()

    log_audit(f"Case {case_id} resolved")

    return jsonify({"status": "resolved"})

# ---------------------------------------------------
# CLEAR CASES (ADMIN ONLY)
# ---------------------------------------------------

@app.route("/clear_cases", methods=["POST"])
@login_required
def clear_cases():

    if current_user.role != "admin":
        return jsonify({"error": "Unauthorized"}), 403

    conn = sqlite3.connect("fronx.db")
    c = conn.cursor()

    c.execute("DELETE FROM cases")
    c.execute("DELETE FROM case_notes")
    c.execute("DELETE FROM case_incidents")
    c.execute("DELETE FROM case_timeline")

    conn.commit()
    conn.close()

    log_audit("All cases cleared")

    return jsonify({"status": "cases_cleared"})

# ---------------------------------------------------
# THREAT INTELLIGENCE API
# ---------------------------------------------------

@app.route("/api/threat_lookup/<path:ip>")
@login_required
def threat_lookup(ip):

    import ipaddress
    import random

    conn = sqlite3.connect("fronx.db")
    c = conn.cursor()

    # ---------------------------
    # CIDR SUPPORT
    # ---------------------------
    try:
        network = ipaddress.ip_network(ip, strict=False)
    except ValueError:
        return jsonify({"error": "Invalid IP or CIDR format"}), 400

    matched_incidents = []

    c.execute("SELECT id, ip, severity FROM incidents")
    all_incidents = c.fetchall()

    for incident in all_incidents:
        incident_ip = incident[1]
        try:
            if ipaddress.ip_address(incident_ip) in network:
                matched_incidents.append(incident)
        except:
            continue

    incident_count = len(matched_incidents)

    # ---------------------------
    # IOC CHECK
    # ---------------------------
    c.execute("SELECT ip FROM iocs")
    ioc_list = [row[0] for row in c.fetchall()]

    ioc_flagged = False

    for i in ioc_list:
        try:
            if "/" not in i:
                if ipaddress.ip_address(i) in network:
                    ioc_flagged = True
                    break
        except ValueError:
        # Skip invalid IOC entries
            continue

    # ---------------------------
    # AI RISK SCORING
    # ---------------------------
    severity_score = 0

    for incident in matched_incidents:
        if incident[2] == "Critical":
            severity_score += 5
        elif incident[2] == "High":
            severity_score += 3
        elif incident[2] == "Medium":
            severity_score += 2
        else:
            severity_score += 1

    # Calculate AI score ONCE
    ai_score = (incident_count * 2) + severity_score


    # ---------------------------
    # MITRE WEIGHT ADDITION
    # ---------------------------

    c.execute("""
        SELECT m.severity_weight
        FROM incident_mitre im
        JOIN mitre_techniques m
        ON im.technique_id = m.technique_id
        JOIN incidents i
        ON i.id = im.incident_id
        WHERE i.ip = ?
    """, (ip,))

    mitre_weights = c.fetchall()

    for w in mitre_weights:
        ai_score += w[0]

    # IOC boost
    if ioc_flagged:
        ai_score += 5

    # Final Risk Classification
    if ai_score >= 15:
        risk = "Critical"
    elif ai_score >= 8:
        risk = "High"
    elif ai_score >= 3:
        risk = "Medium"
    else:
        risk = "Low"


    # ---------------------------
    # GEOIP (Simulated Offline)
    # ---------------------------
    country_map = {
        "192": ("🇮🇳 India", "Kochi"),
        "8": ("🇺🇸 USA", "California"),
        "10": ("Private Network", "Internal"),
        "172": ("Private Network", "Internal"),
        "127": ("Localhost", "Loopback")
    }

    first_octet = str(network.network_address).split(".")[0]
    geo = country_map.get(first_octet, ("Unknown", "Unknown"))

    # ---------------------------
    # THREAT HISTORY TIMELINE
    # ---------------------------
    c.execute("""
        SELECT severity, timestamp
        FROM threat_history
        WHERE ip=?
        ORDER BY id DESC
        LIMIT 10
    """, (ip,))
    history = c.fetchall()

    conn.close()

    log_audit(f"Advanced threat lookup for {ip}")

    return jsonify({
        "ip": ip,
        "risk": risk,
        "ai_score": ai_score,
        "incidents": incident_count,
        "ioc_flagged": ioc_flagged,
        "geo_country": geo[0],
        "geo_city": geo[1],
        "timeline": history
    })

# ---------------------------------------------------
# SYSTEM HEALTH API (FULL INTELLIGENT VERSION)
# ---------------------------------------------------

@app.route("/api/system_health")
@login_required
def system_health():

    import psutil
    import platform
    import socket
    import time
    import statistics

    global high_cpu_start

    # CPU
    cpu_usage = psutil.cpu_percent(interval=1)

    # Memory
    memory = psutil.virtual_memory()
    memory_usage = memory.percent

    # Disk
    disk = psutil.disk_usage('/')
    disk_usage = disk.percent

    # Network
    net = psutil.net_io_counters()

    # Uptime
    boot_time = psutil.boot_time()
    uptime_seconds = int(time.time() - boot_time)

    # Host & OS
    hostname = socket.gethostname()
    os_name = platform.system() + " " + platform.release()

    # ---------------------------------
    # CPU 30 SECOND ALERT TRACKING
    # ---------------------------------

    if "high_cpu_start" not in globals():
        high_cpu_start = None

    if cpu_usage > 80:
        if high_cpu_start is None:
            high_cpu_start = time.time()
    else:
        high_cpu_start = None

    cpu_alert = False
    if high_cpu_start and (time.time() - high_cpu_start) > 30:
        cpu_alert = True

    # ---------------------------------
    # ATTACK MODE DETECTION
    # ---------------------------------

    attack_mode = False
    if cpu_usage > 90 and net.bytes_recv > 10000000:
        attack_mode = True

    # ---------------------------------
    # AI ANOMALY DETECTION
    # ---------------------------------

    if not hasattr(system_health, "cpu_history"):
        system_health.cpu_history = []

    system_health.cpu_history.append(cpu_usage)

    if len(system_health.cpu_history) > 20:
        system_health.cpu_history.pop(0)

    anomaly = False
    if len(system_health.cpu_history) > 5:
        avg = statistics.mean(system_health.cpu_history)
        stdev = statistics.stdev(system_health.cpu_history)
        if cpu_usage > avg + (2 * stdev):
            anomaly = True

    # ---------------------------------
    # SOC HEALTH SCORE
    # ---------------------------------

    score = 100
    if cpu_usage > 80:
        score -= 20
    if memory_usage > 80:
        score -= 20
    if disk_usage > 85:
        score -= 20

    if score >= 80:
        health_status = "Excellent"
    elif score >= 60:
        health_status = "Good"
    elif score >= 40:
        health_status = "Warning"
    else:
        health_status = "Critical"

    return jsonify({
        "cpu_usage": cpu_usage,
        "memory_usage": memory_usage,
        "disk_usage": disk_usage,
        "bytes_sent": net.bytes_sent,
        "bytes_recv": net.bytes_recv,
        "uptime": uptime_seconds,
        "hostname": hostname,
        "os": os_name,
        "health_score": score,
        "health_status": health_status,
        "cpu_alert": cpu_alert,
        "attack_mode": attack_mode,
        "anomaly_detected": anomaly
    })

# ---------------------------------------------------
# MAP INCIDENT TO MITRE
# ---------------------------------------------------

@app.route("/incident/map_mitre/<int:incident_id>", methods=["POST"])
@login_required
def map_mitre(incident_id):

    data = request.json
    technique_id = data.get("technique_id")

    conn = sqlite3.connect("fronx.db")
    c = conn.cursor()

    c.execute("""
        INSERT INTO incident_mitre (incident_id, technique_id)
        VALUES (?, ?)
    """, (incident_id, technique_id))

    conn.commit()
    conn.close()

    log_audit(f"Incident {incident_id} mapped to MITRE {technique_id}")

    return jsonify({"status": "mapped"})
# ---------------------------------------------------
# MITRE HEATMAP DATA
# ---------------------------------------------------

@app.route("/api/mitre_heatmap")
@login_required
def mitre_heatmap():

    conn = sqlite3.connect("fronx.db")
    c = conn.cursor()

    c.execute("""
        SELECT m.technique_id,
               m.technique_name,
               m.tactic,
               COUNT(im.incident_id)
        FROM mitre_techniques m
        LEFT JOIN incident_mitre im
        ON m.technique_id = im.technique_id
        GROUP BY m.technique_id
    """)

    data = c.fetchall()
    conn.close()

    return jsonify(data)

# ---------------------------------------------------
# MAIN
# ---------------------------------------------------

if __name__ == "__main__":

    init_db()

    print("🚀 Starting fronX SOC...")
    print("📡 Starting SSH log monitor...")
    print("🌐 http://localhost:5000/login")

    socketio.start_background_task(monitor_logs, socketio)

    socketio.run(app, host="0.0.0.0", port=5000)
