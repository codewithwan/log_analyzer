# HTTP Log Analyzer Tool

This tool analyzes Apache/Nginx access log files to detect anomalies, generate statistics, and search for specific keywords in the logs. It is designed to help with security monitoring and log file analysis.

## Features

- **Anomaly Detection**: Identifies potential security issues like SQL injection, XSS attempts, and sensitive file access.
- **Log Statistics**: Provides a breakdown of the HTTP methods, status codes, and IP addresses accessing the server.
- **Search Functionality**: Allows you to search for specific IP addresses, URLs, or user-agent strings in the logs.
- **Customizable Date Range**: You can filter logs by start and end date.
- **Anomalous Entries Filtering**: Option to only show log entries with detected anomalies.
- **Multiple Log Files Analysis**: Analyze multiple log files at once.
- **Suspicious User-Agent Report**: Generate a report of suspicious User-Agents.
- **Output to File**: Save the analysis result to an output file.
- **Graphical Representation**: Display a graphical representation of attack patterns.

## Requirements

- Python 3.x
- `argparse`, `re`, `prettytable`, `colorama` modules (all can be installed via `pip`).

```bash
pip install -r requirements.txt
```

## Usage

### Command Line Arguments

```bash
python log_analyzer.py -h
```

### Options:

- `-f`, `--file`: **Required**. Path to the log file to analyze.

  - Example: `--file access.log`

- `-a`, `--only-anomalies`: Display only log entries with anomalies.

  - Example: `--only-anomalies`

- `-s`, `--stats`: Display statistics about the log file (e.g., request count, IP frequencies).

  - Example: `--stats`

- `-sd`, `--start-date`: Filter logs starting from this date (inclusive). Format: `YYYY-MM-DD`.

  - Example: `--start-date 2023-01-01`

- `ed`, `--end-date`: Filter logs up to this date (inclusive). Format: `YYYY-MM-DD`.

  - Example: `--end-date 2023-12-31`

- `-fi`, `--find`: Search for single or multiple keywords (URL, status, etc.).

  - Example: `--find pdf` , `--find sql,200`

- `-rs`, `--regex-search` : Search logs using a regex pattern.

  - Example: `--regex-search 'admin'`

- `--detect` {bruteforce,fileaccess,largefile,directorytraversal,sqli,xss,forbiddenaccess,csrf,ssrf,hightraffic} : Detect specific attack patterns.

  - Example: `--detect bruteforce`

- `-r`,`--report` : Generate a summary report of suspicious IPs.

  - Example: `--report`

- `-ml`, `--multi-log` : Analyze multiple log files.

  - Example: `--multi-log file1.log file2.log`

- `-ua`, `--user-agent-report`: Generate a report of suspicious User-Agents.
  - Example: Example: `--user-agent-report`

- `-o`, `--output`: Output file to save the result. If not provided, the result will be displayed in the terminal.
  - Example: `-o output.txt`

- `-g`, `--graph`: Display a graphical representation of attack patterns.
  - Example: `--graph`

## Example Commands

1. **Analyze logs and show anomalies:**

   ```bash
   python log_analyzer.py --file access.log --only-anomalies
   ```

2. **Generate statistics for the log file:**

   ```bash
   python log_analyzer.py --file access.log --stats
   ```

3. **Search for a specific IP address:**

   ```bash
   python log_analyzer.py --file access.log --find 185.160.71.3
   ```

4. **Filter logs by date range:**

   ```bash
   python log_analyzer.py --file access.log --start-date 2023-01-01 --end-date 2023-12-31
   ```

5. **Save the result to a file:**

   ```bash
   python log_analyzer.py --file access.log --output result.txt
   ```

6. **Display a graphical representation of attack patterns:**

   ```bash
   python log_analyzer.py --file access.log --graph
   ```

## Example Output

When you run the tool, it will display or save a table of log entries with anomalies, including:

| IP Address   | Date                 | Method | URL            | Status | Size | Anomalies                                                  | Rating |
| ------------ | -------------------- | ------ | -------------- | ------ | ---- | ---------------------------------------------------------- | ------ |
| 185.160.71.3 | 01/Jan/2023:12:00:00 | GET    | /admin/config/ | 403    | 1500 | Directory traversal attempt, Sensitive file access attempt | 7      |

### Log Statistics

The statistics option will output the following:

```
=== Statistics ===
Total Requests: 5000

Top 5 IPs:
  185.160.71.3: 300 requests
  192.168.1.1: 200 requests
  ...

HTTP Methods:
  GET: 3500
  POST: 1000
  ...

HTTP Status Codes:
  200: 4500
  403: 300
  500: 200
  ...
```

### Graphical Representation

The graph option will output a graphical representation of attack patterns, such as:

```
====== Attack Graph ======
185.160.71.3 | ██████████████████████████████████████████████ 300
192.168.1.1  | ██████████████████████████████████████████ 200
```

## License

This tool is released under the MIT License.
