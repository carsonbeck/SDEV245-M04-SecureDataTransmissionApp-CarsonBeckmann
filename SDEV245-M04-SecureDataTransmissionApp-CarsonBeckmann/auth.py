import hashlib
import json

def load_users():
    with open("users.json", "r") as f:
        return json.load(f)

def hash_password(password):
    return hashlib.sha256(password.encode()).hexdigest()

def login():
    try:
        users = load_users()
    except FileNotFoundError:
        print("Error: users.json not found.")
        return None, None
    except json.JSONDecodeError:
        print("Error: users.json is malformed.")
        return None, None

    username = input("Username: ")
    password = input("Password: ")

    if username not in users:
        print("Invalid credentials")
        return None, None

    user_data = users[username]
    if hash_password(password) == user_data["password_hash"]:
        print(f"Login successful. Role: {user_data['role']}")
        return username, user_data["role"]
    else:
        print("Invalid credentials")
        return None, None