from Application.security_tool import analyze_logs, write_report


def main():
    report_file, analysis = write_report()
    print(f"Report generated: {report_file}")

    if not analysis["alerts"]:
        print("No suspicious IP activity detected yet.")
        return

    print("Top suspicious IP activity:")
    for alert in analysis["alerts"][:5]:
        print(alert["admin_message"])


if __name__ == "__main__":
    main()
