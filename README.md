# LogTrail

## What it does
LogTrail reads web server access logs, highlights suspicious request patterns, and summarizes useful incident-review signals such as high request volume, 404 bursts, SQL injection attempts, and directory traversal.

---

## How it works
1. **Mock Data Generation**: If no log file exists, the script generates a mock `access.log` containing normal visits alongside three simulated attack signatures.
2. **Signature Detection**: It scans every URL request using **Regular Expressions (Regex)** for:
   * **SQL Injection (SQLi)**: Attempts to trick database queries, looking for signatures like `' OR 1=1`.
   * **Directory Traversal**: Attempts to access system files outside the web directory, looking for patterns like `../../`.
3. **Behavioral Analysis**: It counts and flags IPs that:
   * Send excessive total requests (potential brute-force or DoS indicator).
   * Cause too many 404 (Not Found) errors (indicates a scanner looking for hidden admin directories).

---

## Implementation notes

* `re.compile(...)`: Compiles a regular expression pattern to parse the Common Log Format (CLF) into clean fields (IP, date, method, path, status).
* `urllib.parse.unquote(path)`: Decodes URL-encoded parameters (e.g., converting `%20` to spaces and `%27` to quotes `'`) so the script can match plain-text attack signatures.
* `Counter()` & `defaultdict()`: Tracks frequencies of IP requests and status codes efficiently.

---

## Running it
Run the analyzer from the repo folder. If `access.log` is missing, it creates a small sample log:
```bash
python log_analyzer.py
```


