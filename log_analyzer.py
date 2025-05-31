import os
import re
import urllib.parse
from collections import Counter, defaultdict

# Security Principles:
# 1. Log Auditing: Maintaining detailed logs of system access is critical for post-incident forensics
#    and real-time monitoring. Logs provide visibility into operational anomalies and malicious behaviors.
# 2. Signature Detection: Matching known attack patterns (e.g., directory traversal or SQL injection strings)
#    allows rapid detection of well-documented exploits.
# 3. Behavioral Analysis: Analyzing frequencies of events (e.g., high-rate requests or elevated 404 counts)
#    helps identify automated scanning tools, brute-force attempts, and denial-of-service (DoS) patterns.

# Log pattern for Common Log Format (CLF)
# Format: IP - - [Date] "Method Path Protocol" Status Size
LOG_REGEX = re.compile(
    r'(?P<ip>\S+)\s+\S+\s+\S+\s+\[(?P<date>[^\]]+)\]\s+"(?P<method>\S+)\s+(?P<path>\S+)\s+[^"]+"\s+(?P<status>\d+)\s+(?P<size>\S+)'
)

# Thresholds for behavioral anomaly detection
THRESHOLD_TOTAL_REQUESTS = 20
THRESHOLD_404_ERRORS = 5

# Common attack signatures (case-insensitive)
SQLI_SIGNATURES = [
    r"union\s+select",
    r"select\s+.*\s+from",
    r"'\s+or\s+\d+=\d+",
    r'"\s+or\s+\d+=\d+',
    r"'\s+or\s+'\S+'\s*=\s*'\S+'",
    r"admin'\s*--",
    r"union\s+all\s+select"
]

DIR_TRAVERSAL_SIGNATURES = [
    r"\.\./",
    r"\.\.\\",
    r"/etc/passwd",
    r"/windows/win\.ini",
    r"/boot\.ini"
]

def create_mock_logs(file_path):
    """Creates a mock log file with mixed normal and suspicious entries."""
    mock_data = [
        # Normal requests
        '192.168.1.10 - - [21/Jun/2026:00:01:00 +0530] "GET /index.html HTTP/1.1" 200 1043',
        '192.168.1.10 - - [21/Jun/2026:00:01:05 +0530] "GET /styles.css HTTP/1.1" 200 4500',
        '192.168.1.11 - - [21/Jun/2026:00:01:10 +0530] "GET /images/logo.png HTTP/1.1" 200 12043',
        
        # Directory scanning (High 404s) from 192.168.1.50
        '192.168.1.50 - - [21/Jun/2026:00:02:00 +0530] "GET /admin HTTP/1.1" 404 230',
        '192.168.1.50 - - [21/Jun/2026:00:02:02 +0530] "GET /administrator HTTP/1.1" 404 230',
        '192.168.1.50 - - [21/Jun/2026:00:02:04 +0530] "GET /login.php HTTP/1.1" 404 230',
        '192.168.1.50 - - [21/Jun/2026:00:02:06 +0530] "GET /wp-admin HTTP/1.1" 404 230',
        '192.168.1.50 - - [21/Jun/2026:00:02:08 +0530] "GET /config.bak HTTP/1.1" 404 230',
        '192.168.1.50 - - [21/Jun/2026:00:02:10 +0530] "GET /backup.zip HTTP/1.1" 404 230',
        
        # SQL Injection attempt from 192.168.1.60
        '192.168.1.60 - - [21/Jun/2026:00:03:00 +0530] "GET /search.php?q=books%27%20UNION%20SELECT%20null,username,password%20FROM%20users HTTP/1.1" 200 450',
        
        # Directory Traversal attempt from 192.168.1.70
        '192.168.1.70 - - [21/Jun/2026:00:04:00 +0530] "GET /show_image.php?file=../../../../etc/passwd HTTP/1.1" 400 120',
    ]
    
    # Generate 25 normal requests from 192.168.1.80 (triggers rate detection)
    for i in range(25):
        mock_data.append(
            f'192.168.1.80 - - [21/Jun/2026:00:05:{i:02d} +0530] "GET /api/v1/resource HTTP/1.1" 200 95'
        )
        
    os.makedirs(os.path.dirname(file_path), exist_ok=True)
    with open(file_path, 'w', encoding='utf-8') as f:
        f.write('\n'.join(mock_data) + '\n')
    print(f"[+] Created mock log file at: {file_path}")

def analyze_logs(file_path):
    """Parses and analyzes the log file, generating a structured security summary."""
    if not os.path.exists(file_path):
        print(f"[-] Log file {file_path} not found. Generating mock logs...")
        create_mock_logs(file_path)

    ip_counter = Counter()
    ip_404_counter = Counter()
    flagged_entries = []
    
    print(f"\n[+] Analyzing log file: {file_path}")
    
    with open(file_path, 'r', encoding='utf-8') as f:
        for line_num, line in enumerate(f, 1):
            line = line.strip()
            if not line:
                continue
                
            match = LOG_REGEX.match(line)
            if not match:
                continue
                
            data = match.groupdict()
            ip = data['ip']
            path = data['path']
            status = int(data['status'])
            
            # Increment request counter for IP
            ip_counter[ip] += 1
            
            # Increment 404 counter if status code is 404 or bad request
            if status in (400, 404):
                ip_404_counter[ip] += 1
                
            # URL decode the path to inspect raw parameters
            decoded_path = urllib.parse.unquote(path)
            
            # 1. SQL Injection Check
            for pattern in SQLI_SIGNATURES:
                if re.search(pattern, decoded_path, re.IGNORECASE):
                    flagged_entries.append({
                        'line': line_num,
                        'ip': ip,
                        'type': 'SQL Injection Attempt',
                        'detail': decoded_path,
                        'raw': line
                    })
                    break  # Avoid double flagging the same line
                    
            # 2. Directory Traversal Check
            for pattern in DIR_TRAVERSAL_SIGNATURES:
                if re.search(pattern, decoded_path, re.IGNORECASE):
                    flagged_entries.append({
                        'line': line_num,
                        'ip': ip,
                        'type': 'Directory Traversal Attempt',
                        'detail': decoded_path,
                        'raw': line
                    })
                    break

    # Compile Analysis Summary
    print("\n" + "="*80)
    print(" LOG ANALYSIS SECURITY REPORT")
    print("="*80)
    
    # 1. High Volume Request Detection (Brute Force / DoS indicators)
    print("\n[!] Top Active IPs (Rate Detection):")
    rate_limiting_triggered = False
    for ip, count in ip_counter.most_common():
        status_str = ""
        if count > THRESHOLD_TOTAL_REQUESTS:
            status_str = f" [ALERT: High request volume - {count} requests]"
            rate_limiting_triggered = True
        print(f"  - {ip}: {count} requests{status_str}")
    if not rate_limiting_triggered:
        print("  - No IPs exceeded the rate threshold.")

    # 2. Directory Scanning Detection (404 Spikes)
    print("\n[!] Directory Scanning Indicators (Elevated 404/400 Status Codes):")
    scanning_detected = False
    for ip, count in ip_404_counter.items():
        if count > THRESHOLD_404_ERRORS:
            print(f"  - {ip}: {count} error codes [ALERT: Scan/enumeration suspected]")
            scanning_detected = True
    if not scanning_detected:
        print("  - No IPs exceeded the error/scan threshold.")

    # 3. Signature-Based Flags (SQLi, Directory Traversal)
    print("\n[!] Flagged Malicious Requests (Signature Detection):")
    if flagged_entries:
        for entry in flagged_entries:
            print(f"  - Line {entry['line']} | IP: {entry['ip']} | Type: {entry['type']}")
            print(f"    Payload: {entry['detail']}")
    else:
        print("  - No request signatures matched known attacks.")
        
    print("\n" + "="*80 + "\n")

if __name__ == "__main__":
    log_file = os.path.join(os.path.dirname(os.path.abspath(__file__)), "access.log")
    analyze_logs(log_file)
