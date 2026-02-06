# IT-360-Group-Project
Digital Forensics tool to help administrators create login logs to analyze to help prevent intrusions from attackers.

## Team Members
- Laney Dunker
- Danniella Agyeman
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

## Timeline
- Week 1-3: Build the bones of the application we will be working in, begin storage mechanism for attempts and other information for the logs
- Week 4-6: Write the code for tracking attempts and working on the logic for system
- Week 7-9: Implement AI (We are not yet exactly sure how we will be doing this)
- Week 10-12: Finish up the project and report

