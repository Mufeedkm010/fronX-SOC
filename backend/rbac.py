roles = {
    "admin": "admin",
    "analyst": "analyst"
}

permissions = {
    "admin": ["view", "export", "block"],
    "analyst": ["view"]
}

def has_permission(user_role, action):
    return action in permissions.get(user_role, [])
