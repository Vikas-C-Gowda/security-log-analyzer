import re
from collections import Counter

LOG_FILE = "sample_logs/access.log"


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

def main():
    log_lines = read_log_file(LOG_FILE)

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

if __name__ == "__main__":
    main()