# Import key functions, constants, and data from your security_tool module
from Application.security_tool import (
    MAX_ATTEMPTS,
    USERS,
    admin_unlock,
    login,
    write_report,
)

# Module for providing options, handling the login attempt, allowing the admin to lock the account and other executive functions of the module. 
def main():
    while True:
        print("\nFailed Login Monitoring Tool")
        print("--------------------------------")
        print("1. Login")
        print("2. Admin Unlock")
        print("3. Generate Admin Report")
        print("4. List Demo Users")
        print("5. Exit")

        choice = input("Select option: ")

        if choice == "1":
            username = input("Username: ")
            password = input("Password: ")
            ip = input("IP Address (press Enter to use stored/default IP): ").strip()
            ip = ip or None

            _, message = login(username, password, ip)
            print(message)

        elif choice == "2":
            username = input("Enter username to unlock: ")
            _, message = admin_unlock(username)
            print(message)

        elif choice == "3":
            report_file, analysis = write_report()
            print(f"Report written to {report_file}")
            for alert in analysis["alerts"][:3]:
                print(alert["admin_message"])

        elif choice == "4":
            print(f"Max failed attempts before lockout: {MAX_ATTEMPTS}")
            for username, profile in USERS.items():
                print(f"- {username} ({profile['role']}) registered IP: {profile['registered_ip']}")

        elif choice == "5":
            break

        else:
            print("Invalid choice.")


if __name__ == "__main__":
    main()
