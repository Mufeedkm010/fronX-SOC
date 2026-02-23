import requests

def get_ip_info(ip):

    # Local / Private IP fallback
    if ip.startswith("127.") or ip.startswith("192.") or ip.startswith("10."):
        return "Localhost | 20.5937 | 78.9629"

    try:
        response = requests.get(f"http://ip-api.com/json/{ip}", timeout=3)
        data = response.json()

        if data["status"] == "success":
            country = data.get("country", "Unknown")
            lat = data.get("lat", 0)
            lon = data.get("lon", 0)

            return f"{country} | {lat} | {lon}"

        else:
            return "Unknown | 20.5937 | 78.9629"

    except:
        return "Error | 20.5937 | 78.9629"
