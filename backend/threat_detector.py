def detect_threat(message):
    keywords = [
        "failed password",
        "invalid user",
        "authentication failure",
        "error",
        "attack"
    ]

    for word in keywords:
        if word in message.lower():
            return "Medium"

    return "Low"
