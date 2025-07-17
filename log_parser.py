import re

def parse_logs(log_file):
    print(f'[*] Analyzing SIEM logs: {log_file}')
    failed_attempts = {}
    mock_logs = [
        '2025-07-17 10:01:22 Invalid user admin from 192.168.1.50 port 44322 ssh2',
        '2025-07-17 10:01:25 Invalid user admin from 192.168.1.50 port 44326 ssh2',
        '2025-07-17 10:01:28 Invalid user admin from 192.168.1.50 port 44330 ssh2',
        '2025-07-17 10:02:01 Accepted publickey for analyst from 10.0.0.15 port 51221 ssh2'
    ]
    for log in mock_logs:
        if 'Invalid user' in log:
            match = re.search(r'from (\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})', log)
            if match:
                ip = match.group(1)
                failed_attempts[ip] = failed_attempts.get(ip, 0) + 1

    for ip, count in failed_attempts.items():
        if count >= 3:
            print(f'[!] ALERT: Brute Force Detected from IP: {ip} ({count} failed attempts)')

if __name__ == '__main__':
    parse_logs('auth.log')
