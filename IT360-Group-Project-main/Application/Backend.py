import sqlite3
import os

# Configuration 
DB_NAME = "login.db"  
REPORT_FILE = "Logs.txt"

def load_data():
	"""Load event data from the SQLite database safely."""
	if not os.path.exists(DB_NAME):
		return 0, 0, []

	try:
		# Ensure databsse exists before attempting connection
    		conn = sqlite3.connect(DB_NAME)
    		c = conn.cursor()

    		c.execute("SELECT event_type, username, password, ip, user_agent, timestamp FROM events")
    		rows = c.fetchall()

    		clicks = sum(1 for r in rows if r[0] == "link_click")
    		submissions = sum(1 for r in rows if r[0] == "credential_submission")

    		return clicks, submissions, rows

	except Exception as e:
		# Basic error handling for database failures
    		print("Database Error:", e)
    		return 0, 0, []


def ai_analyze(clicks, submissions):
	"""AI-style weighted scoring model."""
	score = 0

# AI “rules”
	score += clicks * 20
	score += submissions * 70

# AI thresholds
	if score == 0:
    		severity = "LOW"
    		explanation = "No user interaction detected. Low likelihood of social engineering success."
    		mitigations = [
        		"Continue general cybersecurity training.",
        		"Send periodic reminders about checking URLs."
    ]

	elif score <= 40:
    		severity = "MEDIUM"
    		explanation = "User clicked the phishing link but did not enter credentials."
    		mitigations = [
        		"Provide phishing recognition training.",
        		"Enable browser warnings for suspicious websites."
    ]

	elif score <= 100:
    		severity = "HIGH"
    		explanation = "Credentials were submitted — strong indicator of susceptibility."
    		mitigations = [
        		"Require immediate phishing awareness training.",
        		"Enable multi-factor authentication (MFA).",
        		"Review password reset procedures."
    ]

	else:
    		severity = "CRITICAL"
    		explanation = "Multiple submissions or repeated interactions indicate severe risk."
    		mitigations = [
        		"Conduct full security training for the user.",
        		"Force credential resets immediately.",
        		"Enforce MFA organization-wide.",
        		"Run repeated controlled phishing simulations."
    ]

	return score, severity, explanation, mitigations


def write_report(clicks, submissions, score, severity, explanation, mitigations, rows):
	"""Write the AI-generated report to a text file."""
	with open(REPORT_FILE, "w") as f:
		f.write("AI-Enhanced Phishing Simulation Report\n")
		f.write("=====================================\n\n")
		f.write(f"Total Link Clicks: {clicks}\n")
		f.write(f"Total Credentials Submitted: {submissions}\n")
		f.write(f"AI Severity Score: {score}\n")
		f.write(f"Severity Level: {severity}\n\n")
		f.write("AI Reasoning:\n")
		f.write(f"- {explanation}\n\n")
		f.write("Recommended Mitigation Steps:\n")
		for m in mitigations:
			f.write(f"- {m}\n")
		f.write("\n\nEvent Log Details:\n")
		for r in rows:
			f.write(str(r) + "\n")

	print("AI-based Logs.txt generated successfully!")

def run():
	clicks, submissions, rows = load_data()
	score, severity, explanation, mitigations = ai_analyze(clicks, submissions)
	write_report(clicks, submissions, score, severity, explanation, mitigations, rows)

if __name__ == "__main__":
	run()
