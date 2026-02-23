import os

SECRET_KEY = "fronx_enterprise"
DATABASE = "fronx.db"

# Get absolute base directory of project
BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

# Correct absolute log path
LOG_FILE = os.path.join(BASE_DIR, "logs", "monitored.log")

EMAIL_SENDER = "your_email@gmail.com"
EMAIL_PASSWORD = "your_app_password"
EMAIL_RECEIVER = "your_email@gmail.com"
