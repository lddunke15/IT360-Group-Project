import os
import sys

from flask import Flask, redirect, render_template, request, url_for

# Get current file path and project root directory 
CURRENT_DIR = os.path.dirname(os.path.abspath(__file__))
PROJECT_ROOT = os.path.dirname(CURRENT_DIR)

# Add project root to system path (So we can import other modules)
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)

# Import security functions and variabels from custom module
from Application.security_tool import (  # noqa: E402
    MAX_ATTEMPTS,
    USERS,
    admin_unlock,
    analyze_logs,
    load_state,
    login as process_login,
    write_report,
)

# Creat Flask App
app = Flask(__name__)


def get_client_ip():
    # Get real IP address (handles proxies/load balancers)
    forwarded_for = request.headers.get("X-Forwarded-For", "")
    # If forwarded IP exists return first one 
    if forwarded_for:
        return forwarded_for.split(",")[0].strip()
    # Otherwise use direct client IP
    return request.remote_addr or "127.0.0.1"


@app.route("/")
def landing():
    # Load anaylsis data for dashboard 
    analysis = analyze_logs()
    # Render login page wiht data 
    return render_template(
        "login.html",
        message=None,
        analysis=analysis,
        max_attempts=MAX_ATTEMPTS,
        users=sorted(USERS.keys()),
    )


@app.route("/login", methods=["POST"])
def login():
    # Get form input from user 
    username = request.form.get("username", "").strip()
    password = request.form.get("password", "")
    # Process login attempt 
    success, message = process_login(username, password, get_client_ip())
    # Recalculate anaylisys after login attempt 
    analysis = analyze_logs()
    # Reload login page wiht result message 
    return render_template(
        "login.html",
        message=message,
        success=success,
        analysis=analysis,
        max_attempts=MAX_ATTEMPTS,
        users=sorted(USERS.keys()),
    )


@app.route("/admin")
def admin_dashboard():
    #Load anaylsis and system state
    analysis = analyze_logs()
    state = load_state()
    #Show admin dashboard 
    return render_template(
        "admin.html",
        analysis=analysis,
        lockouts=state["lockouts"], # Users cureenlty lock out
        users=sorted(USERS.keys()),
        message=request.args.get("message"),
    )


@app.route("/admin/unlock", methods=["POST"])
def unlock_user():
    # Get username to unlock 
    username = request.form.get("username", "").strip()
    # Unlock user account 
    _, message = admin_unlock(username)
    # Redirect back to admin dashboard with message 
    return redirect(url_for("admin_dashboard", message=message))


@app.route("/admin/report", methods=["POST"])
def generate_report():
    # Generate phishing/security report 
    report_file, _ = write_report()
    #Redirect with confirmation message 
    return redirect(url_for("admin_dashboard", message=f"Report generated at {report_file}"))

# Run Flask App 
if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=True)
