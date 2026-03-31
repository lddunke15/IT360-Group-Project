import json
import time
from datetime import datetime, timedelta
import hashlib

MAX_ATTEMPTS = 5
LOCKOUT_DURATION = 900  # 15 minutes (seconds)
LOG_FILE = "login_logs.json"

#In Memory Database
users = {
    "admin": hashlib.sha256("password123".encode()).hexdigest(),
    "user1": hashlib.sha256("securepass".encode()).hexdigest()
}

failed_attempts = {}   # {username: [timestamps]}
lockouts = {}         # {username: lockout_end_time}

#Log Function
def log_attempt(username, ip, status, attempted_password, locked=False):
    log_entry = {
        "timestamp": datetime.now().isoformat(),
        "username": username,
        "ip": ip,
        "status": status,
        "attempted_password_hash": hashlib.sha256(attempted_password.encode()).hexdigest(),
        "locked": locked
    }

    try:
        with open(LOG_FILE, "r") as f:
            logs = json.load(f)
    except:
        logs = []

    logs.append(log_entry)

    with open(LOG_FILE, "w") as f:
        json.dump(logs, f, indent=4)

#Check Logout
def is_locked(username):
    if username in lockouts:
        if datetime.now() < lockouts[username]:
            return True
        else:
            del lockouts[username]
    return False

#Record Failed Attempt
def record_failed_attempt(username):
    now = datetime.now()

    if username not in failed_attempts:
        failed_attempts[username] = []

    failed_attempts[username].append(now)

    # Keep only recent attempts (last 15 minutes)
    window = now - timedelta(seconds=LOCKOUT_DURATION)
    failed_attempts[username] = [
        t for t in failed_attempts[username] if t > window
    ]

    if len(failed_attempts[username]) >= MAX_ATTEMPTS:
        lockouts[username] = now + timedelta(seconds=LOCKOUT_DURATION)
        return True

    return False

#Login Function
def login(username, password, ip):
    if username not in users:
        print("User does not exist.")
        return False

    if is_locked(username):
        print("Account is locked. Try again later.")
        log_attempt(username, ip, "locked", password, locked=True)
        return False

    hashed_input = hashlib.sha256(password.encode()).hexdigest()

    if users[username] == hashed_input:
        print("Login successful!")
        failed_attempts[username] = []
        log_attempt(username, ip, "success", password)
        return True
    else:
        locked = record_failed_attempt(username)
        log_attempt(username, ip, "failed", password, locked)

        if locked:
            print("Too many failed attempts. Account locked.")
        else:
            print("Invalid credentials.")

        return False

#Admin Unlock Function
def admin_unlock(username):
    if username in lockouts:
        del lockouts[username]
        failed_attempts[username] = []
        print(f"{username} has been unlocked.")
    else:
        print("User is not locked.")
#CLI Interface
def main():
    while True:
        print("\n1. Login")
        print("2. Admin Unlock")
        print("3. Exit")

        choice = input("Select option: ")

        if choice == "1":
            username = input("Username: ")
            password = input("Password: ")
            ip = input("IP Address: ")

            login(username, password, ip)

        elif choice == "2":
            username = input("Enter username to unlock: ")
            admin_unlock(username)

        elif choice == "3":
            break

        else:
            print("Invalid choice.")

if __name__ == "__main__":
    main()
