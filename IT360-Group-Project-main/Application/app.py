import os
import sys

from flask import Flask, redirect, render_template, request, url_for


CURRENT_DIR = os.path.dirname(os.path.abspath(__file__))
PROJECT_ROOT = os.path.dirname(CURRENT_DIR)
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)

from Application.security_tool import (  # noqa: E402
    MAX_ATTEMPTS,
    USERS,
    admin_unlock,
    analyze_logs,
    load_state,
    login as process_login,
    write_report,
)


app = Flask(__name__)


def get_client_ip():
    forwarded_for = request.headers.get("X-Forwarded-For", "")
    if forwarded_for:
        return forwarded_for.split(",")[0].strip()
    return request.remote_addr or "127.0.0.1"


@app.route("/")
def landing():
    analysis = analyze_logs()
    return render_template(
        "login.html",
        message=None,
        analysis=analysis,
        max_attempts=MAX_ATTEMPTS,
        users=sorted(USERS.keys()),
    )


@app.route("/login", methods=["POST"])
def login():
    username = request.form.get("username", "").strip()
    password = request.form.get("password", "")
    success, message = process_login(username, password, get_client_ip())
    analysis = analyze_logs()
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
    analysis = analyze_logs()
    state = load_state()
    return render_template(
        "admin.html",
        analysis=analysis,
        lockouts=state["lockouts"],
        users=sorted(USERS.keys()),
        message=request.args.get("message"),
    )


@app.route("/admin/unlock", methods=["POST"])
def unlock_user():
    username = request.form.get("username", "").strip()
    _, message = admin_unlock(username)
    return redirect(url_for("admin_dashboard", message=message))


@app.route("/admin/report", methods=["POST"])
def generate_report():
    report_file, _ = write_report()
    return redirect(url_for("admin_dashboard", message=f"Report generated at {report_file}"))


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=True)
