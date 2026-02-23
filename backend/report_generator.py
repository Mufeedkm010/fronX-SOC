import os
import sqlite3
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table
from reportlab.lib.styles import getSampleStyleSheet
from reportlab.lib import colors
from reportlab.lib.units import inch

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DB_PATH = os.path.join(BASE_DIR, "fronx.db")
REPORT_PATH = os.path.join(BASE_DIR, "incident_report.pdf")

def generate_report():

    doc = SimpleDocTemplate(REPORT_PATH)
    elements = []

    styles = getSampleStyleSheet()
    elements.append(Paragraph("fronX Enterprise Incident Report", styles["Heading1"]))
    elements.append(Spacer(1, 0.3 * inch))

    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute("""
        SELECT timestamp, threat_level, geo_info, message 
        FROM logs 
        ORDER BY id DESC 
        LIMIT 50
    """)
    rows = c.fetchall()
    conn.close()

    data = [["Time", "Threat", "Geo", "Message"]]
    for row in rows:
        data.append([str(row[0]), str(row[1]), str(row[2]), str(row[3])[:80]])

    table = Table(data)
    elements.append(table)

    doc.build(elements)

    return REPORT_PATH
