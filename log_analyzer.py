import argparse
import os
import re
from collections import Counter
from prettytable import PrettyTable
from datetime import datetime

# Parsing log format
def parse_log_entry(entry):
    pattern = r'(?P<ip>\d+\.\d+\.\d+\.\d+) - - \[(?P<date>.*?)\] "(?P<method>\w+) (?P<url>.*?) HTTP/.*?" (?P<status>\d+) (?P<size>\d+) ".*?" "(?P<user_agent>.*?)"'
    match = re.match(pattern, entry)
    if match:
        return match.groupdict()
    return None

# Sanitize log entry
def sanitize_log_entry(entry):
    entry['url'] = re.sub(r'[^\w\s\-\/\.\?\=\&]', '', entry['url'])
    entry['user_agent'] = re.sub(r'[^\w\s\-\/\.\;\(\)]', '', entry['user_agent'])
    return entry

# Deteksi anomali
def detect_anomalies(log_entry):
    anomalies = []
    rating = 0

    if re.search(r'(\.\./|\.\.\\)', log_entry['url']):
        anomalies.append('Directory traversal attempt')
        rating += 3

    if re.search(r'(\b(?:SELECT|INSERT|UPDATE|DELETE|DROP|UNION|--|#)\b)', log_entry['url'], re.IGNORECASE):
        anomalies.append('SQL injection attempt')
        rating += 5

    if re.search(r'(\b(?:<script>|</script>|javascript:|onload=|onerror=)\b)', log_entry['url'], re.IGNORECASE):
        anomalies.append('XSS attempt')
        rating += 4

    if re.search(r'(\b(?:admin|root|config|passwd|shadow)\b)', log_entry['url'], re.IGNORECASE):
        anomalies.append('Sensitive file access attempt')
        rating += 4

    if re.search(r'(\b(?:\d{4}-\d{2}-\d{2}|\d{2}/\d{2}/\d{4})\b)', log_entry['url']):
        anomalies.append('Date pattern in URL')
        rating += 2

    if log_entry['status'] == '403':
        anomalies.append('Forbidden access detected')
        rating += 2

    if log_entry['status'] == '500':
        anomalies.append('Server error detected')
        rating += 1

    if int(log_entry['size']) > 1000000:
        anomalies.append('Large data transfer detected')
        rating += 1

    return anomalies, rating

# Pencarian berdasarkan kata kunci
def find_in_logs(log_entries, search_term):
    found_entries = []
    for entry in log_entries:
        # Mencari dalam IP, URL, atau User-Agent
        if (search_term in entry['ip'] or
            search_term in entry['url'] or
            search_term in entry['user_agent']):
            found_entries.append(entry)
    return found_entries

# Analisis log
def analyze_log(file_path, only_anomalies=False, start_date=None, end_date=None):
    if not os.path.exists(file_path):
        raise FileNotFoundError(f"File {file_path} not found.")

    log_entries = []
    with open(file_path, 'r') as file:
        for line in file:
            parsed_entry = parse_log_entry(line)
            if parsed_entry:
                parsed_entry = sanitize_log_entry(parsed_entry)
                entry_date = datetime.strptime(parsed_entry['date'], '%d/%b/%Y:%H:%M:%S %z')
                if start_date and entry_date < start_date:
                    continue
                if end_date and entry_date > end_date:
                    continue
                anomalies, rating = detect_anomalies(parsed_entry)
                parsed_entry['anomalies'] = anomalies
                parsed_entry['rating'] = rating
                log_entries.append(parsed_entry)

    if only_anomalies:
        log_entries = [entry for entry in log_entries if entry['anomalies']]

    return log_entries

# Statistik log
def generate_statistics(log_entries):
    total_requests = len(log_entries)
    ip_counter = Counter(entry['ip'] for entry in log_entries)
    method_counter = Counter(entry['method'] for entry in log_entries)
    status_counter = Counter(entry['status'] for entry in log_entries)

    stats = {
        'total_requests': total_requests,
        'ip_counter': ip_counter,
        'method_counter': method_counter,
        'status_counter': status_counter
    }
    return stats

# Tampilkan laporan
def display_log_entries(log_entries):
    table = PrettyTable()
    table.field_names = ["IP", "Date", "Method", "URL", "Status", "Size", "Anomalies", "Rating"]

    for entry in log_entries:
        anomalies = ", ".join(entry['anomalies']) if entry['anomalies'] else "None"
        table.add_row([entry['ip'],
                       entry['date'],
                       entry['method'],
                       entry['url'],
                       entry['status'],
                       entry['size'],
                       anomalies,
                       entry['rating']])

    return table

# Tampilkan statistik
def display_statistics(stats):
    output = []
    output.append("\n=== Statistics ===")
    output.append(f"Total Requests: {stats['total_requests']}")
    output.append("\nTop 5 IPs:")
    for ip, count in stats['ip_counter'].most_common(5):
        output.append(f"  {ip}: {count} requests")
    output.append("\nHTTP Methods:")
    for method, count in stats['method_counter'].items():
        output.append(f"  {method}: {count}")
    output.append("\nHTTP Status Codes:")
    for status, count in stats['status_counter'].items():
        output.append(f"  {status}: {count}")
    
    return "\n".join(output)

# Main function
def main():
    parser = argparse.ArgumentParser(
        description="HTTP Log Analyzer Tool",
        formatter_class=argparse.RawTextHelpFormatter
    )
    parser.add_argument(
        "--file", 
        required=True, 
        help="Path to the log file (required).\nExample: --file access.log"
    )
    parser.add_argument(
        "--only-anomalies", 
        action="store_true", 
        help="Display only entries with anomalies.\nExample: --only-anomalies"
    )
    parser.add_argument(
        "--stats", 
        action="store_true", 
        help="Display statistics of the log file.\nExample: --stats"
    )
    parser.add_argument(
        "--start-date", 
        help="Filter logs starting from this date (inclusive). Format: YYYY-MM-DD\nExample: --start-date 2023-01-01"
    )
    parser.add_argument(
        "--end-date", 
        help="Filter logs up to this date (inclusive). Format: YYYY-MM-DD\nExample: --end-date 2023-12-31"
    )
    parser.add_argument(
        "--find", 
        help="Search for a keyword (IP, URL, etc.). Example: --find 185.160.71.3"
    )
    parser.add_argument(
        "-o", "--output", 
        help="Output file to save the result. If not provided, the result is displayed in the terminal.\nExample: -o output.txt"
    )
    args = parser.parse_args()

    start_date = datetime.strptime(args.start_date, '%Y-%m-%d') if args.start_date else None
    end_date = datetime.strptime(args.end_date, '%Y-%m-%d') if args.end_date else None

    try:
        log_entries = analyze_log(args.file, args.only_anomalies, start_date, end_date) 
        if args.find:
            log_entries = find_in_logs(log_entries, args.find)

        if args.stats:
            stats = generate_statistics(log_entries)
            result = display_statistics(stats)
        else:
            result = display_log_entries(log_entries)

        if args.output:
            with open(args.output, 'w') as output_file:
                output_file.write(result)
            print(f"Output saved to {args.output}")
        else:
            print(result)

    except FileNotFoundError as e:
        print(f"Error: {e}")

if __name__ == "__main__":
    main()
