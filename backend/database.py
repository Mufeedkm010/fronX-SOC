import sqlite3


def init_db():

    conn = sqlite3.connect("fronx.db")
    c = conn.cursor()

    # ---------------------------------------------------
    # LOGS TABLE
    # ---------------------------------------------------

    c.execute("""
        CREATE TABLE IF NOT EXISTS logs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp TEXT,
            message TEXT,
            threat_level TEXT,
            geo_info TEXT
        )
    """)

    # ---------------------------------------------------
    # INCIDENTS TABLE
    # ---------------------------------------------------

    c.execute("""
        CREATE TABLE IF NOT EXISTS incidents (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            created_at TEXT,
            ip TEXT,
            severity TEXT,
            status TEXT DEFAULT 'Open',
            assigned_to TEXT,
            notes TEXT
        )
    """)

    # ---------------------------------------------------
    # IOC TABLE
    # ---------------------------------------------------

    c.execute("""
        CREATE TABLE IF NOT EXISTS iocs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    ip TEXT UNIQUE,
    status TEXT DEFAULT 'Active'
        )
    """)

    # ---------------------------------------------------
    # CASES TABLE
    # ---------------------------------------------------

    c.execute("""
        CREATE TABLE IF NOT EXISTS cases (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            created_at TEXT,
            title TEXT,
            status TEXT DEFAULT 'Open',
            assigned_to TEXT
        )
    """)

    # ---------------------------------------------------
    # CASE NOTES TABLE
    # ---------------------------------------------------

    c.execute("""
        CREATE TABLE IF NOT EXISTS case_notes (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            case_id INTEGER,
            note TEXT,
            created_at TEXT,
            created_by TEXT,
            FOREIGN KEY (case_id) REFERENCES cases(id)
        )
    """)

    # ---------------------------------------------------
    # CASE ↔ INCIDENT LINK TABLE
    # ---------------------------------------------------

    c.execute("""
        CREATE TABLE IF NOT EXISTS case_incidents (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            case_id INTEGER,
            incident_id INTEGER,
            FOREIGN KEY (case_id) REFERENCES cases(id),
            FOREIGN KEY (incident_id) REFERENCES incidents(id)
        )
    """)

    # ---------------------------------------------------
    # CASE TIMELINE TABLE
    # ---------------------------------------------------

    c.execute("""
        CREATE TABLE IF NOT EXISTS case_timeline (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            case_id INTEGER,
            action TEXT,
            timestamp TEXT,
            performed_by TEXT,
            FOREIGN KEY (case_id) REFERENCES cases(id)
        )
    """)

    # ---------------------------------------------------
    # AUDIT LOGS TABLE
    # ---------------------------------------------------

    c.execute("""
        CREATE TABLE IF NOT EXISTS audit_logs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp TEXT,
            user TEXT,
            action TEXT
        )
    """)

    # ---------------------------------------------------
    # SETTINGS TABLE
    # ---------------------------------------------------

    c.execute("""
        CREATE TABLE IF NOT EXISTS settings (
            id INTEGER PRIMARY KEY,
            ai_sensitivity INTEGER DEFAULT 5,
            log_retention_days INTEGER DEFAULT 30,
            honeypot_autostart INTEGER DEFAULT 0
        )
    """)
    # ---------------------------------------------------
    # THREAT HISTORY TABLE
    # ---------------------------------------------------

    c.execute("""
        CREATE TABLE IF NOT EXISTS threat_history (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            ip TEXT,
            severity TEXT,
            timestamp TEXT
        )
    """)

    # Insert default settings if not exists
    c.execute("SELECT COUNT(*) FROM settings")
    if c.fetchone()[0] == 0:
        c.execute("""
            INSERT INTO settings
            (id, ai_sensitivity, log_retention_days, honeypot_autostart)
            VALUES (1, 5, 30, 0)
        """)
        # ---------------------------------------------------
    # MITRE ATT&CK TECHNIQUES TABLE
    # ---------------------------------------------------

    c.execute("""
        CREATE TABLE IF NOT EXISTS mitre_techniques (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            technique_id TEXT UNIQUE,
            technique_name TEXT,
            tactic TEXT,
            severity_weight INTEGER DEFAULT 3
        )
    """)

    # ---------------------------------------------------
    # INCIDENT ↔ MITRE LINK TABLE
    # ---------------------------------------------------

    c.execute("""
        CREATE TABLE IF NOT EXISTS incident_mitre (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            incident_id INTEGER,
            technique_id TEXT,
            FOREIGN KEY (incident_id) REFERENCES incidents(id)
        )
    """)

    # ---------------------------------------------------
    # INSERT DEFAULT MITRE DATA
    # ---------------------------------------------------

    c.execute("SELECT COUNT(*) FROM mitre_techniques")
    if c.fetchone()[0] == 0:
        techniques = [
            ("T1110", "Brute Force", "Credential Access", 5),
            ("T1059", "Command and Scripting Interpreter", "Execution", 4),
            ("T1078", "Valid Accounts", "Persistence", 4),
            ("T1021", "Remote Services", "Lateral Movement", 3),
            ("T1046", "Network Service Scanning", "Discovery", 2)
        ]

        c.executemany("""
            INSERT INTO mitre_techniques
            (technique_id, technique_name, tactic, severity_weight)
            VALUES (?, ?, ?, ?)
        """, techniques)


    conn.commit()
    conn.close()
