import subprocess

blocked_ips = set()

def block_ip(ip):

    # Do not block localhost or private ranges
    if ip.startswith("127.") or ip.startswith("192.168.") or ip.startswith("10."):
        print(f"⚠️ Skipping block for local IP: {ip}")
        return

    if ip in blocked_ips:
        return

    try:
        subprocess.run(
            ["sudo", "iptables", "-A", "INPUT", "-s", ip, "-j", "DROP"],
            check=True
        )
        blocked_ips.add(ip)
        print(f"🚫 Blocked IP: {ip}")
    except Exception as e:
        print("Firewall error:", e)
