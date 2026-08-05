import re
from collections import Counter
import sys
from datetime import datetime

class Colors:
    RED = "\033[91m"
    GREEN = "\033[92m"
    YELLOW = "\033[93m"
    BLUE = "\033[94m"
    CYAN = "\033[96m"
    RESET = "\033[0m"

DEFAULT_LOG_FILE = "sample_logs/access.log"

def read_log_file(file_path):
    try:
        with open(file_path, "r") as file:
            return file.readlines()
    except FileNotFoundError:
        print(f"[ERROR] Log file not found: {file_path}")
        return []
    
LOG_PATTERN = (
    r'(\S+) - - \[(.*?)\] '
    r'"(\S+) (.*?) \S+" '
    r'(\d{3}) (\d+)'
)

def parse_log_line(line):
    match = re.match(LOG_PATTERN, line)

    if not match:
        return None

    return {
        "ip": match.group(1),
        "timestamp": match.group(2),
        "method": match.group(3),
        "path": match.group(4),
        "status": int(match.group(5)),
        "size": int(match.group(6))
    }

def show_statistics(parsed_logs):
    total_requests = len(parsed_logs)

    methods = Counter(log["method"] for log in parsed_logs)
    status_codes = Counter(log["status"] for log in parsed_logs)

    print("\n===== Log Statistics =====")
    print(f"Total Requests : {total_requests}")

    print("\nHTTP Methods:")
    for method, count in methods.items():
        print(f"  {method}: {count}")

    print("\nStatus Codes:")
    for status, count in status_codes.items():
        print(f"  {status}: {count}")

def detect_failed_logins(parsed_logs):
    failed_logins = []

    for log in parsed_logs:
        if log["method"] == "POST" and log["path"] == "/login" and log["status"] == 401:
            failed_logins.append(log)

    print("\n===== Failed Login Attempts =====")

    if not failed_logins:
        print("No failed login attempts found.")
        return

    print(f"Total Failed Logins: {len(failed_logins)}\n")

    for log in failed_logins:
        print(
            f"IP: {log['ip']} | "
            f"Time: {log['timestamp']} | "
            f"Path: {log['path']}"
        )

def detect_brute_force(parsed_logs):
    failed_ips = []

    for log in parsed_logs:
        if log["method"] == "POST" and log["path"] == "/login" and log["status"] == 401:
            failed_ips.append(log["ip"])

    ip_counts = Counter(failed_ips)

    print("\n===== Brute Force Detection =====")

    found = False

    for ip, count in ip_counts.items():
        if count >= 3:
            found = True
            print(f"⚠️ Suspicious IP: {ip} ({count} failed login attempts)")

    if not found:
        print("No brute-force attacks detected.")

def detect_suspicious_status_codes(parsed_logs):
    suspicious_statuses = {403, 404, 500}

    print("\n===== Suspicious HTTP Status Codes =====")

    found = False

    for log in parsed_logs:
        if log["status"] in suspicious_statuses:
            found = True
            print(
                f"IP: {log['ip']} | "
                f"Status: {log['status']} | "
                f"Path: {log['path']} | "
                f"Time: {log['timestamp']}"
            )

    if not found:
        print("No suspicious HTTP status codes found.")

def generate_security_summary(parsed_logs):
    total_requests = len(parsed_logs)

    failed_logins = sum(
        1 for log in parsed_logs
        if log["method"] == "POST"
        and log["path"] == "/login"
        and log["status"] == 401
    )

    brute_force_ips = set()

    ip_failures = Counter(
        log["ip"]
        for log in parsed_logs
        if log["method"] == "POST"
        and log["path"] == "/login"
        and log["status"] == 401
    )

    for ip, count in ip_failures.items():
        if count >= 3:
            brute_force_ips.add(ip)

    suspicious_statuses = sum(
        1 for log in parsed_logs
        if log["status"] in [403, 404, 500]
    )

    print(f"\n{Colors.CYAN}========== Security Summary =========={Colors.RESET}")
    print(f"{Colors.BLUE}Total Requests           : {Colors.RESET}{total_requests}")
    print(f"{Colors.YELLOW}Failed Login Attempts    : {Colors.RESET}{failed_logins}")
    print(f"{Colors.RED}Brute Force IPs Detected : {Colors.RESET}{len(brute_force_ips)}")
    print(f"{Colors.RED}Suspicious Status Events : {Colors.RESET}{suspicious_statuses}")

def show_top_active_ips(parsed_logs):
    ip_counter = Counter(log["ip"] for log in parsed_logs)

    print("\n===== Top Active IP Addresses =====")

    for ip, count in ip_counter.most_common(5):
        print(f"{ip} : {count} requests")

def generate_text_report(parsed_logs):
    ip_counter = Counter(log["ip"] for log in parsed_logs)

    failed_logins = sum(
        1 for log in parsed_logs
        if log["method"] == "POST"
        and log["path"] == "/login"
        and log["status"] == 401
    )

    brute_force_ips = [
        ip for ip, count in ip_counter.items() if count >= 3
    ]

    suspicious_events = [
        log for log in parsed_logs
        if log["status"] in [403, 404, 500]
    ]

    report_path = "reports/security_report.txt"

    with open(report_path, "w") as report:
        report.write("===== Security Log Analysis Report =====\n\n")
        report.write(f"Total Requests: {len(parsed_logs)}\n")
        report.write(f"Failed Login Attempts: {failed_logins}\n")
        report.write(f"Brute Force IPs: {len(brute_force_ips)}\n")
        report.write(f"Suspicious Status Events: {len(suspicious_events)}\n\n")

        report.write("Top Active IPs:\n")
        for ip, count in ip_counter.most_common(5):
            report.write(f" - {ip}: {count} requests\n")

    print(f"\nText report generated: {report_path}")

def generate_html_report(parsed_logs):
    total_requests = len(parsed_logs)

    ip_counter = Counter(log["ip"] for log in parsed_logs)
    top_ips = ip_counter.most_common(5)

    method_counter = Counter(log["method"] for log in parsed_logs)

    failed_logins = sum(
        1 for log in parsed_logs
        if log["method"] == "POST"
        and log["path"] == "/login"
        and log["status"] == 401
    )

    suspicious_events = sum(
        1 for log in parsed_logs
        if log["status"] in [403, 404, 500]
    )

    report_time = datetime.now().strftime("%d %b %Y | %I:%M:%S %p")

    if suspicious_events >= 3:
        overall_risk = "HIGH"
        risk_color = "#dc3545"
        risk_message = "Multiple suspicious events detected. Immediate investigation is recommended."
    elif suspicious_events >= 1:
        overall_risk = "MEDIUM"
        risk_color = "#fd7e14"
        risk_message = "Some suspicious activities were detected. Review the affected requests."
    else:
        overall_risk = "LOW"
        risk_color = "#28a745"
        risk_message = "No suspicious security events detected."

    html = f"""
<!DOCTYPE html>
<html>
<head>
<title>Security Log Report</title>

<style>
body {{
    font-family: Arial;
    background:#f4f4f4;
    margin:40px;
}}

.container {{
    background:white;
    padding:30px;
    border-radius:10px;
}}

table {{
    width:100%;
    border-collapse:collapse;
    margin-top:20px;
}}

th,td {{
    border:1px solid #ccc;
    padding:10px;
}}

th {{
    background:#333;
    color:white;
}}

h1 {{
    color:#1f4e79;
}}

.cards{{
    display:flex;
    gap:20px;
    margin:25px 0;
}}

.card{{
    flex:1;
    background:#eef6ff;
    padding:15px;
    border-radius:10px;
    text-align:center;
    box-shadow:0 2px 6px rgba(0,0,0,0.1);
}}

.card h3{{
    margin:0;
    color:#1f4e79;
}}

.card p{{
    font-size:24px;
    font-weight:bold;
    margin-top:12px;
}}

.success{{
    background:#28a745;
    color:white;
    padding:5px 10px;
    border-radius:20px;
    font-weight:bold;
}}

.warning{{
    background:#ffc107;
    color:black;
    padding:5px 10px;
    border-radius:20px;
    font-weight:bold;
}}

.danger{{
    background:#dc3545;
    color:white;
    padding:5px 10px;
    border-radius:20px;
    font-weight:bold;
}}

.info{{
    background:#17a2b8;
    color:white;
    padding:5px 10px;
    border-radius:20px;
    font-weight:bold;
}}

.high-risk{{
    color:#dc3545;
    font-weight:bold;
}}

.medium-risk{{
    color:#fd7e14;
    font-weight:bold;
}}

.low-risk{{
    color:#17a2b8;
    font-weight:bold;
}}

.safe{{
    color:#28a745;
    font-weight:bold;
}}

.summary-box{{
    margin:25px 0;
    padding:18px;
    border-left:6px solid;
    background:#f8f9fa;
    border-radius:8px;
}}

.rank{{
    text-align:center;
    font-weight:bold;
}}

.requests{{
    text-align:center;
}}

.ip-column{{
    text-align:center;
}}

.method{{
    text-align:center;
}}

.count{{
    text-align:center;
}}

</style>

</head>

<body>

<div class="container">

<h1>Security Log Analysis Report</h1>

<p style="color:gray; margin-top:-10px;">
Generated: {report_time}
</p>

<div class="summary-box" style="border-color:{risk_color};">
<h3>Overall Security Risk: <span style="color:{risk_color};">{overall_risk}</span></h3>
<p>{risk_message}</p>
</div>

<div class="cards">

<div class="card">
<h3>Total Requests</h3>
<p>{total_requests}</p>
</div>

<div class="card">
<h3>Failed Logins</h3>
<p>{failed_logins}</p>
</div>

<div class="card">
<h3>Suspicious Events</h3>
<p>{suspicious_events}</p>
</div>

</div>
"""
    
    html += """
<h2>Top Active IPs</h2>

<table>
<tr>
<th>Rank</th>
<th>IP Address</th>
<th>Requests</th>
</tr>
"""

    rank = 1

    for ip, count in top_ips:
        html += f"""
<tr>
<td class="rank">{rank}</td>
<td class="ip-column">{ip}</td>
<td class="requests">{count}</td>
</tr>
"""
        rank += 1

    html += """
    </table>
"""
    html += """
<h2>Request Method Summary</h2>

<table>
<tr>
<th>Method</th>
<th>Count</th>
</tr>
"""

    for method, count in method_counter.items():
        html += f"""
<tr>
<td class="method">{method}</td>
<td class="count">{count}</td>
</tr>
"""
    html += """
</table>
"""

    html += """
<table>

<tr>
<th>IP Address</th>
<th>Method</th>
<th>Path</th>
<th>Status</th>
<th>Risk</th>
</tr>
    """
    for log in parsed_logs:

        status = log["status"]

        if status == 200:
            badge = '<span class="success">200</span>'
        elif status in [401, 403]:
            badge = f'<span class="warning">{status}</span>'
        elif status >= 500:
            badge = f'<span class="danger">{status}</span>'
        else:
            badge = f'<span class="info">{status}</span>'

        if status >= 500:
            risk = '<span class="high-risk">HIGH</span>'
        elif status in [401, 403]:
            risk = '<span class="medium-risk">MEDIUM</span>'
        elif status == 404:
            risk = '<span class="low-risk">LOW</span>'
        else:
            risk = '<span class="safe">SAFE</span>'

        html += f"""
<tr>
<td>{log['ip']}</td>
<td>{log['method']}</td>
<td>{log['path']}</td>
<td>{badge}</td>
<td>{risk}</td>
</tr>
    """

    html += """
</table>

</div>

</body>
</html>
    """

    report_path = "reports/security_report.html"

    with open(report_path, "w", encoding="utf-8") as file:
        file.write(html)

    print(f"\nHTML report generated: {report_path}")

def assess_ip_risk(parsed_logs):
    print("\n===== IP Risk Assessment =====")

    ip_data = {}

    for log in parsed_logs:
        ip = log["ip"]

        if ip not in ip_data:
            ip_data[ip] = {
                "requests": 0,
                "failed_logins": 0,
                "suspicious_events": 0
            }

        ip_data[ip]["requests"] += 1

        if (
            log["method"] == "POST"
            and log["path"] == "/login"
            and log["status"] == 401
        ):
            ip_data[ip]["failed_logins"] += 1

        if log["status"] in [403, 404, 500]:
            ip_data[ip]["suspicious_events"] += 1

    for ip, data in ip_data.items():
        score = (
            data["failed_logins"] * 2
            + data["suspicious_events"]
        )

        if score >= 6:
            risk = "HIGH"
        elif score >= 3:
            risk = "MEDIUM"
        else:
            risk = "LOW"

        print(
            f"{ip} -> {risk} | "
            f"Requests: {data['requests']}, "
            f"Failed Logins: {data['failed_logins']}, "
            f"Suspicious Events: {data['suspicious_events']}"
        )

def detect_directory_scanning(parsed_logs):
    sensitive_paths = [
        "/admin",
        "/login",
        "/phpmyadmin",
        "/config",
        "/.git",
        "/.env"
    ]

    print("\n===== Directory Scanning Detection =====")

    found = False

    for log in parsed_logs:
        if log["path"] in sensitive_paths:
            found = True
            print(
                f"IP: {log['ip']} | "
                f"Path: {log['path']} | "
                f"Status: {log['status']} | "
                f"Time: {log['timestamp']}"
            )

    if not found:
        print("No directory scanning detected.")

def generate_security_findings(parsed_logs):
    print("\n========== Security Findings ==========")

    findings = []

    ip_failures = Counter()
    directory_scan = Counter()

    for log in parsed_logs:
        if (
            log["method"] == "POST"
            and log["path"] == "/login"
            and log["status"] == 401
        ):
            ip_failures[log["ip"]] += 1

            findings.append(
                ("MEDIUM", f"Failed login attempt from {log['ip']}")
            )

        if log["path"] in ["/admin", "/phpmyadmin", "/.git", "/.env"]:
            directory_scan[log["ip"]] += 1

            findings.append(
                ("MEDIUM", f"Sensitive path accessed: {log['path']} from {log['ip']}")
            )

        if log["status"] in [403, 404, 500]:
            findings.append(
                ("LOW", f"HTTP {log['status']} on {log['path']} from {log['ip']}")
            )

    for ip, count in ip_failures.items():
        if count >= 3:
            findings.append(
                ("HIGH", f"Possible brute-force attack from {ip} ({count} failed logins)")
            )

    for ip, count in directory_scan.items():
        if count >= 3:
            findings.append(
                ("HIGH", f"Possible directory scanning from {ip} ({count} sensitive paths accessed)")
            )

    if not findings:
        print("No security findings.")
        return

    severity_order = {
        "HIGH": 3,
        "MEDIUM": 2,
        "LOW": 1
    }

    findings.sort(key=lambda x: severity_order[x[0]], reverse=True)

    for severity, message in findings:
        if severity == "HIGH":
            color = Colors.RED
        elif severity == "MEDIUM":
            color = Colors.YELLOW
        else:
            color = Colors.GREEN

        print(f"{color}[{severity}]{Colors.RESET} {message}")

def main():
    if len(sys.argv) > 1:
        log_file = sys.argv[1]
    else:
        log_file = DEFAULT_LOG_FILE

    print(f"\nAnalyzing log file: {log_file}")

    log_lines = read_log_file(log_file)

    print(f"Total log entries: {len(log_lines)}\n")

    parsed_logs = []

    for line in log_lines:
        log = parse_log_line(line)

        if log:
            parsed_logs.append(log)

    print(f"Successfully parsed: {len(parsed_logs)} entries\n")

    for log in parsed_logs[:5]:
        print(log)

    show_statistics(parsed_logs)
    detect_failed_logins(parsed_logs)
    detect_brute_force(parsed_logs)
    detect_suspicious_status_codes(parsed_logs)
    generate_security_summary(parsed_logs)
    show_top_active_ips(parsed_logs)
    generate_text_report(parsed_logs)
    generate_html_report(parsed_logs)
    assess_ip_risk(parsed_logs)
    detect_directory_scanning(parsed_logs)
    generate_security_findings(parsed_logs)

if __name__ == "__main__":
    main()