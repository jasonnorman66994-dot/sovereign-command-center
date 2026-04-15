# Advanced Mail Log Analysis Script
# Extracts spikes, suspicious attachments, and rapid sending for visualization

import re
import csv
from collections import Counter, defaultdict
from datetime import datetime

logfile = 'maillog.txt'  # Update with your log file path
sender_counter = Counter()
attachment_counter = Counter()
hourly_activity = defaultdict(int)
login_attempts = []  # For login analysis

with open(logfile) as f:
    for line in f:
        # Extract sender
        m = re.search(r'from=<([^>]+)>', line)
        if m:
            sender = m.group(1)
            sender_counter[sender] += 1
        # Extract attachment
        a = re.search(r'attachment=([\w.]+)', line)
        if a:
            attachment_counter[a.group(1)] += 1
        # Extract timestamp and count per hour
        t = re.match(r'([A-Z][a-z]{2} +\d+ \d{2}:\d{2}:\d{2})', line)
        if t and m:
            try:
                dt = datetime.strptime(t.group(1), '%b %d %H:%M:%S')
            except ValueError:
                continue
            key = (dt.strftime('%b %d %H'), sender)
            hourly_activity[key] += 1
        # Extract login attempts (IMAP/POP3/SMTP)
        login = re.match(r'([A-Z][a-z]{2} +\d+ \d{2}:\d{2}:\d{2}) .* (LOGIN (FAILED|SUCCESS)) user=([^ ]+) host=([\d.]+)', line)
        if login:
            ts, status, _, user, ip = login.group(1), login.group(3), login.group(4), login.group(5), login.group(6)
            login_attempts.append({'timestamp': ts, 'user': user, 'ip': ip, 'status': status})

# Output CSV for mail activity
with open('mail_activity.csv', 'w', newline='') as csvfile:
    writer = csv.writer(csvfile)
    writer.writerow(['Hour', 'Sender', 'Count'])
    for (hour, sender), count in hourly_activity.items():
        writer.writerow([hour, sender, count])

# Output CSV for login attempts
with open('login_attempts.csv', 'w', newline='') as csvfile:
    writer = csv.DictWriter(csvfile, fieldnames=['timestamp', 'user', 'ip', 'status'])
    writer.writeheader()
    for row in login_attempts:
        writer.writerow(row)

print('Top senders:', sender_counter.most_common(5))
print('Top attachments:', attachment_counter.most_common(5))
print('CSV output: mail_activity.csv, login_attempts.csv')
