import re
from datetime import datetime, timedelta
from collections import defaultdict

# Configuration
LOG_FILE = "logs/auth.log"
FAILED_LIMIT = 5          # Number of failed attempts
TIME_WINDOW = 2           # Time window in minutes

# Regex pattern to match failed login attempts
pattern = r"(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}) Failed login from ([\d.]+)"

failed_attempts = defaultdict(list)

# Read log file
with open(LOG_FILE, "r") as file:
    for line in file:
        match = re.search(pattern, line)
        if match:
            timestamp = datetime.strptime(match.group(1), "%Y-%m-%d %H:%M:%S")
            ip = match.group(2)
            failed_attempts[ip].append(timestamp)

print("\n🔍 Brute Force Detection Report\n")

# Detect brute force behavior
for ip, times in failed_attempts.items():
    times.sort()
    for i in range(len(times)):
        window = times[i:i + FAILED_LIMIT]
        if len(window) == FAILED_LIMIT:
            if window[-1] - window[0] <= timedelta(minutes=TIME_WINDOW):
                print("⚠️ Brute-force attack detected!")
                print(f"IP Address : {ip}")
                print(f"Attempts   : {FAILED_LIMIT} within {TIME_WINDOW} minutes\n")
                break
