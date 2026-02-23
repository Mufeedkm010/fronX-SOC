from flask_login import LoginManager, UserMixin

# ---------------------------------------------------
# Login Manager
# ---------------------------------------------------

login_manager = LoginManager()


# ---------------------------------------------------
# User Class
# ---------------------------------------------------

class User(UserMixin):

    def __init__(self, username, role):
        self.id = username
        self.role = role

    # Helper role checks (used in SOC controls)
    def is_admin(self):
        return self.role == "admin"

    def is_analyst(self):
        return self.role == "analyst"

    def is_viewer(self):
        return self.role == "viewer"


# ---------------------------------------------------
# In-Memory Users (Upgrade Later to DB)
# ---------------------------------------------------

users = {

    "admin": {
        "password": "admin123",
        "role": "admin"
    },

    "analyst": {
        "password": "analyst123",
        "role": "analyst"
    },

    "viewer": {
        "password": "viewer123",
        "role": "viewer"
    }
}


# ---------------------------------------------------
# User Loader
# ---------------------------------------------------

@login_manager.user_loader
def load_user(user_id):

    if user_id in users:
        role = users[user_id]["role"]
        return User(user_id, role)

    return None
