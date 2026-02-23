from collections import defaultdict
import time
from firewall import block_ip

attempt_tracker = defaultdict(list)

THRESHOLD = 5
WINDOW = 60  # seconds

def detect_bruteforce(ip):

    now = time.time()
    attempt_tracker[ip].append(now)

    # Keep attempts within time window
    attempt_tracker[ip] = [
        t for t in attempt_tracker[ip]
        if now - t <= WINDOW
    ]

    if len(attempt_tracker[ip]) >= THRESHOLD:
        block_ip(ip)
        print(f"🚫 Brute-force detected and blocked: {ip}")
        attempt_tracker[ip] = []
