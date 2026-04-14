# IT-360-Group-Project
Digital Forensics tool to help administrators create login logs to analyze to help prevent intrusions from attackers.

## Team Members
- Laney Dunker
- Daniella Agyeman
- Jonah Morgan

## Full Project Idea
We will be creating a tool that will detect and list the number of failed login attempts and the correlating IP addresses for the failed attempts for an application. The number of failed attempts, IP addresses, and failed passwords will be stored into a log for administration analysis. This tool will have a feature that will lock a user out after a set number of failed attempts until an administrator allows them to reattempt login.

## Tools Needed  
- Python 
  Developing the login system, lockout policy,and logging functionality. 
- VMware
  Used to create an isolated testing lab with multiple machines.
    - VM 1: Application
    - VM 2: Kali Linux (attacker/testing)
    - VM 3: Admin workstation (monitoring)
- Kail Linux
  Used to simulate real-world attack scenarios such as credential stuffing correltion and attack patterns.
- Machine Learning Libraries (scikit-learn, pandas)  
  Used to analyze failed login attempt data and assist in identifying anomalous or high-risk login behavior.

## Potential Idea for AI Integration
- Using AI to track patterns and find which ones are concerning
  - How many attempts from certain IP addresses
  - Time between attempts
  - How close the password attempted actually was to the correct one
  - Generate message for admin

## Timeline
- Week 1-3: Build the bones of the application we will be working in, begin storage mechanism for attempts and other information for the logs
- Week 4-6: Write the code for tracking attempts and working on the logic for system
- Week 7-9: Implement AI (We are not yet exactly sure how we will be doing this)
- Week 10-12: Finish up the project and report

# How to run
pip install python
python app.py
Open the site in your browser:
http://127.0.0.1:5000/ for the login page
http://127.0.0.1:5000/admin for the admin dashboard

## Project Overview
This project is a Python-based cybersecurity tool designed to monitor failed login attempts, identify suspicious authentication behavior, and support administrative response.

The system records:
- Failed login attempts
- The correlating IP addresses
- Failed password data in a protected/logged form
- The timing and frequency of repeated attempts
- Whether an account becomes locked after too many failed attempts

The tool also performs AI-style behavioral analysis by identifying patterns that may be concerning, such as:
- High numbers of attempts from the same IP address
- Very short time gaps between repeated login attempts
- Password guesses that are unusually close to the correct password
- Repeated targeting of the same or multiple usernames

This allows administrators to review both the raw logs and a summarized report of suspicious activity.

## Main Security Features
- Tracks failed login attempts per user
- Records the source IP address for each login attempt
- Locks a user account after a set number of failed attempts
- Keeps the user locked until an administrator unlocks them
- Generates a log for administration analysis
- Analyzes suspicious IP behavior
- Measures time between repeated attempts
- Scores how close attempted passwords are to the correct password pattern
- Generates an alert-style message for administrators
- Provides both a CLI version and a web-based server version

## How It Works
When a login attempt is made, the system:
1. Collects the username and password attempt
2. Captures the IP address of the source
3. Checks whether the account exists
4. Checks whether the account is currently locked
5. Verifies whether the password is correct
6. Logs the event details
7. Increments failed-attempt counters when needed
8. Locks the account after too many failed attempts
9. Analyzes the stored log data for suspicious patterns
10. Generates an admin-readable report and alert messages

