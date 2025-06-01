# LogTrail

## What it does
LogTrail reads web server access logs, highlights suspicious request patterns, and summarizes useful incident-review signals such as high request volume, 404 bursts, SQL injection attempts, and directory traversal.

---

## 🚪 The Analogy
Imagine a guard at a castle gate who writes down the name, time, and request of every single person trying to enter. If a suspicious visitor keeps asking to access the king's private chambers, or tries to enter the gate 50 times in one second, the guard flags them. The **Log Analyzer** is the manager who reviews the guard's logbook at the end of the day to identify anomalies and attacks.

---

## ⚙️ How it Works
1. **Mock Data Generation**: If no log file exists, the script generates a mock `access.log` containing normal visits alongside three simulated attack signatures.
2. **Signature Detection**: It scans every URL request using **Regular Expressions (Regex)** for:
   * **SQL Injection (SQLi)**: Attempts to trick database queries, looking for signatures like `' OR 1=1`.
   * **Directory Traversal**: Attempts to access system files outside the web directory, looking for patterns like `../../`.
3. **Behavioral Analysis**: It counts and flags IPs that:
   * Send excessive total requests (potential brute-force or DoS indicator).
   * Cause too many 404 (Not Found) errors (indicates a scanner looking for hidden admin directories).

---

## 🛠️ Code Breakdown

* `re.compile(...)`: Compiles a regular expression pattern to parse the Common Log Format (CLF) into clean fields (IP, date, method, path, status).
* `urllib.parse.unquote(path)`: Decodes URL-encoded parameters (e.g., converting `%20` to spaces and `%27` to quotes `'`) so the script can match plain-text attack signatures.
* `Counter()` & `defaultdict()`: Tracks frequencies of IP requests and status codes efficiently.

---

## 🚀 How to Run
Run the script to analyze the server logs. If `access.log` is missing, it will create one automatically for demonstration:
```bash
python log_analyzer.py
```
