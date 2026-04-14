import hashlib
import json
import os
from collections import defaultdict
from datetime import datetime


BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
LOG_FILE = os.path.join(BASE_DIR, "login_logs.json")
STATE_FILE = os.path.join(BASE_DIR, "auth_state.json")
REPORT_FILE = os.path.join(BASE_DIR, "Logs.txt")
MAX_ATTEMPTS = 5


def hash_password(password):
    return hashlib.sha256(password.encode("utf-8")).hexdigest()


USERS = {
    "admin": {
        "password_hash": hash_password("password123"),
        "role": "admin",
        "registered_ip": "10.0.0.10",
    },
    "user1": {
        "password_hash": hash_password("securepass"),
        "role": "user",
        "registered_ip": "10.0.0.21",
    },
    "Laney": {
        "password_hash": hash_password("pink"),
        "role": "user",
        "registered_ip": "10.0.0.31",
    },
    "Daniela": {
        "password_hash": hash_password("green"),
        "role": "user",
        "registered_ip": "10.0.0.32",
    },
    "Jonah": {
        "password_hash": hash_password("purple"),
        "role": "user",
        "registered_ip": "10.0.0.33",
    },
}


def now_iso():
    return datetime.utcnow().isoformat()


def load_json_file(path, default):
    if not os.path.exists(path):
        return default

    try:
        with open(path, "r", encoding="utf-8") as file:
            return json.load(file)
    except (json.JSONDecodeError, OSError):
        return default


def save_json_file(path, payload):
    with open(path, "w", encoding="utf-8") as file:
        json.dump(payload, file, indent=4)


def load_logs():
    return load_json_file(LOG_FILE, [])


def append_log(entry):
    logs = load_logs()
    logs.append(entry)
    save_json_file(LOG_FILE, logs)


def load_state():
    default = {"failed_attempts": {}, "lockouts": {}}
    return load_json_file(STATE_FILE, default)


def save_state(state):
    save_json_file(STATE_FILE, state)


def similarity_ratio(value_a, value_b):
    if not value_a and not value_b:
        return 1.0

    if not value_a or not value_b:
        return 0.0

    rows = len(value_a) + 1
    cols = len(value_b) + 1
    matrix = [[0] * cols for _ in range(rows)]

    for index in range(rows):
        matrix[index][0] = index

    for index in range(cols):
        matrix[0][index] = index

    for row in range(1, rows):
        for col in range(1, cols):
            cost = 0 if value_a[row - 1] == value_b[col - 1] else 1
            matrix[row][col] = min(
                matrix[row - 1][col] + 1,
                matrix[row][col - 1] + 1,
                matrix[row - 1][col - 1] + cost,
            )

    edit_distance = matrix[-1][-1]
    longest = max(len(value_a), len(value_b))
    return 1 - (edit_distance / longest)


def get_user(username):
    return USERS.get(username)


def resolve_ip(username, provided_ip=None):
    if provided_ip:
        return provided_ip

    user = get_user(username)
    if user:
        return user["registered_ip"]

    return "127.0.0.1"


def is_locked(username):
    state = load_state()
    return username in state["lockouts"]


def record_failed_attempt(username, ip):
    state = load_state()
    failed_attempts = state["failed_attempts"].get(username, [])
    failed_attempts.append({"timestamp": now_iso(), "ip": ip})
    state["failed_attempts"][username] = failed_attempts

    if len(failed_attempts) >= MAX_ATTEMPTS:
        state["lockouts"][username] = {
            "locked_at": now_iso(),
            "reason": f"{len(failed_attempts)} failed attempts",
        }
        save_state(state)
        return True, len(failed_attempts)

    save_state(state)
    return False, len(failed_attempts)


def clear_failed_attempts(username):
    state = load_state()
    state["failed_attempts"][username] = []
    save_state(state)


def build_log_entry(
    username,
    ip,
    status,
    attempted_password,
    similarity,
    failed_count,
    locked,
    include_password_details=True,
):
    password_preview = ""
    password_hash = ""

    if include_password_details:
        password_preview = attempted_password[:2] + "*" * max(len(attempted_password) - 2, 0)
        password_hash = hash_password(attempted_password)

    return {
        "timestamp": now_iso(),
        "username": username,
        "ip": ip,
        "status": status,
        "failed_attempt_number": failed_count,
        "attempted_password_preview": password_preview,
        "attempted_password_hash": password_hash,
        "password_similarity_percent": round(similarity * 100, 2),
        "locked": locked,
    }


def login(username, password, ip=None):
    user = get_user(username)
    client_ip = resolve_ip(username, ip)

    if not user:
        entry = build_log_entry(username, client_ip, "unknown_user", password, 0.0, 0, False)
        append_log(entry)
        return False, "User does not exist."

    if is_locked(username):
        entry = build_log_entry(username, client_ip, "locked", password, 0.0, 0, True)
        append_log(entry)
        return False, "Account is locked until an administrator unlocks it."

    similarity = similarity_ratio(password, recover_demo_password(user["password_hash"]))
    if user["password_hash"] == hash_password(password):
        clear_failed_attempts(username)
        entry = build_log_entry(
            username,
            client_ip,
            "success",
            "",
            0.0,
            0,
            False,
            include_password_details=False,
        )
        append_log(entry)
        return True, "Login successful."

    locked, failed_count = record_failed_attempt(username, client_ip)
    entry = build_log_entry(username, client_ip, "failed", password, similarity, failed_count, locked)
    append_log(entry)

    if locked:
        return False, f"Too many failed attempts. {username} is locked until admin unlock."

    remaining = MAX_ATTEMPTS - failed_count
    return False, f"Invalid credentials. {remaining} attempts remaining before lockout."


def admin_unlock(username):
    state = load_state()

    if username not in state["lockouts"]:
        return False, "User is not locked."

    del state["lockouts"][username]
    state["failed_attempts"][username] = []
    save_state(state)
    append_log(
        {
            "timestamp": now_iso(),
            "username": username,
            "ip": resolve_ip(username),
            "status": "admin_unlock",
            "failed_attempt_number": 0,
            "attempted_password_preview": "",
            "attempted_password_hash": "",
            "password_similarity_percent": 0,
            "locked": False,
        }
    )
    return True, f"{username} has been unlocked."


def recover_demo_password(password_hash):
    for username, data in USERS.items():
        if data["password_hash"] == password_hash:
            demo_passwords = {
                "admin": "password123",
                "user1": "securepass",
                "Laney": "pink",
                "Daniela": "green",
                "Jonah": "purple",
            }
            return demo_passwords[username]
    return ""


def summarize_ip_activity(logs):
    grouped = defaultdict(list)
    for entry in logs:
        if entry["status"] in {"failed", "locked", "unknown_user"}:
            grouped[entry["ip"]].append(entry)

    summaries = []
    for ip, attempts in grouped.items():
        attempts = sorted(attempts, key=lambda item: item["timestamp"])
        timestamps = [datetime.fromisoformat(item["timestamp"]) for item in attempts]
        gaps = []
        for first, second in zip(timestamps, timestamps[1:]):
            gaps.append((second - first).total_seconds())

        summaries.append(
            {
                "ip": ip,
                "attempt_count": len(attempts),
                "usernames": sorted({item["username"] for item in attempts}),
                "average_seconds_between_attempts": round(sum(gaps) / len(gaps), 2) if gaps else None,
                "minimum_seconds_between_attempts": round(min(gaps), 2) if gaps else None,
                "closest_password_similarity": max(
                    (item.get("password_similarity_percent", 0) for item in attempts),
                    default=0,
                ),
            }
        )
    return sorted(summaries, key=lambda item: item["attempt_count"], reverse=True)


def calculate_risk(ip_summary):
    score = 0
    score += min(ip_summary["attempt_count"] * 12, 60)

    min_gap = ip_summary["minimum_seconds_between_attempts"]
    if min_gap is not None and min_gap < 10:
        score += 25
    elif min_gap is not None and min_gap < 60:
        score += 10

    if len(ip_summary["usernames"]) > 1:
        score += 20

    if ip_summary["closest_password_similarity"] >= 80:
        score += 20
    elif ip_summary["closest_password_similarity"] >= 50:
        score += 10

    if score >= 80:
        return score, "CRITICAL"
    if score >= 55:
        return score, "HIGH"
    if score >= 30:
        return score, "MEDIUM"
    return score, "LOW"


def generate_admin_message(ip_summary, severity, score):
    usernames = ", ".join(ip_summary["usernames"]) or "unknown users"
    average_gap = ip_summary["average_seconds_between_attempts"]
    gap_text = "single attempt observed" if average_gap is None else f"average gap {average_gap} seconds"
    similarity = ip_summary["closest_password_similarity"]

    return (
        f"[{severity}] IP {ip_summary['ip']} generated {ip_summary['attempt_count']} failed attempts "
        f"against {usernames}; {gap_text}; closest attempted password matched {similarity}% of the "
        f"real password pattern. Recommended action: review the source IP, keep impacted accounts locked "
        f"if needed, and reset credentials when similarity is unusually high. Risk score: {score}."
    )


def analyze_logs():
    logs = load_logs()
    ip_summaries = summarize_ip_activity(logs)
    alerts = []

    for summary in ip_summaries:
        score, severity = calculate_risk(summary)
        alerts.append(
            {
                "ip": summary["ip"],
                "severity": severity,
                "risk_score": score,
                "attempt_count": summary["attempt_count"],
                "usernames": summary["usernames"],
                "average_seconds_between_attempts": summary["average_seconds_between_attempts"],
                "minimum_seconds_between_attempts": summary["minimum_seconds_between_attempts"],
                "closest_password_similarity": summary["closest_password_similarity"],
                "admin_message": generate_admin_message(summary, severity, score),
            }
        )

    totals = {
        "total_events": len(logs),
        "failed_attempts": sum(1 for item in logs if item["status"] == "failed"),
        "locked_attempts": sum(1 for item in logs if item["status"] == "locked"),
        "successful_logins": sum(1 for item in logs if item["status"] == "success"),
        "unknown_user_attempts": sum(1 for item in logs if item["status"] == "unknown_user"),
    }

    return {"totals": totals, "alerts": alerts, "logs": logs}


def write_report():
    analysis = analyze_logs()
    with open(REPORT_FILE, "w", encoding="utf-8") as report:
        report.write("Failed Login Monitoring Report\n")
        report.write("================================\n\n")
        report.write(f"Total Events: {analysis['totals']['total_events']}\n")
        report.write(f"Failed Attempts: {analysis['totals']['failed_attempts']}\n")
        report.write(f"Locked Attempts: {analysis['totals']['locked_attempts']}\n")
        report.write(f"Successful Logins: {analysis['totals']['successful_logins']}\n")
        report.write(f"Unknown User Attempts: {analysis['totals']['unknown_user_attempts']}\n\n")

        if not analysis["alerts"]:
            report.write("No suspicious failed-login patterns have been logged yet.\n")
        else:
            report.write("Suspicious IP Analysis\n")
            report.write("----------------------\n")
            for alert in analysis["alerts"]:
                report.write(f"IP Address: {alert['ip']}\n")
                report.write(f"Severity: {alert['severity']} (score {alert['risk_score']})\n")
                report.write(f"Attempts: {alert['attempt_count']}\n")
                report.write(f"Users Targeted: {', '.join(alert['usernames'])}\n")
                report.write(
                    "Average Seconds Between Attempts: "
                    f"{alert['average_seconds_between_attempts']}\n"
                )
                report.write(
                    "Closest Password Similarity: "
                    f"{alert['closest_password_similarity']}%\n"
                )
                report.write(f"Admin Message: {alert['admin_message']}\n\n")

        report.write("Detailed Log Entries\n")
        report.write("--------------------\n")
        for entry in analysis["logs"]:
            report.write(json.dumps(entry) + "\n")

    return REPORT_FILE, analysis
