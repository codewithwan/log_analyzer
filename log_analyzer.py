import argparse
import os
import re
from collections import Counter
from prettytable import PrettyTable
from datetime import datetime
from colorama import Fore, Style, init

init()

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

# Detect Anomalies
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

# Search with keyword
def find_in_logs(log_entries, search_terms):
    terms = search_terms.split(',')
    return [entry for entry in log_entries if all(term in entry['url'] or term in entry['status'] for term in terms)]

# Search with regex pattern
def advanced_regex_search(log_entries, regex_pattern):
    pattern = re.compile(regex_pattern)
    return [entry for entry in log_entries if pattern.search(entry['url']) or pattern.search(entry['user_agent'])]

# Group IPs by activity
def group_ips_by_activity(log_entries):
    ip_activity = {}
    for entry in log_entries:
        ip = entry['ip']
        if ip not in ip_activity:
            ip_activity[ip] = []
        ip_activity[ip].append(entry)
    return ip_activity

# Detect attack patterns
def detect_attack_patterns(log_entries, attack_type):
    attack_patterns = {
        'bruteforce': re.compile(r'login|signin|password|admin', re.IGNORECASE),
        'fileaccess': re.compile(r'\.sqlite|\.log|\.db|\.pdf|\.sql', re.IGNORECASE),
    }
    if attack_type not in attack_patterns:
        raise ValueError(f"Unknown attack type: {attack_type}")

    attack_stats = Counter()
    url_stats = Counter()
    pattern = attack_patterns[attack_type]
    for entry in log_entries:
        if pattern.search(entry['url']):
            attack_stats[entry['ip']] += 1
            url_stats[entry['url']] += 1

    if attack_type == 'bruteforce':
        attack_stats = {ip: count for ip, count in attack_stats.items() if count >= 5}

    return attack_stats, url_stats

# Analyze large log file
def analyze_large_log(file_path, chunk_size=1024):
    log_entries = []
    try:
        with open(file_path, 'r') as file:
            while chunk := file.read(chunk_size):
                for line in chunk.splitlines():
                    parsed_entry = parse_log_entry(line)
                    if parsed_entry:
                        parsed_entry = sanitize_log_entry(parsed_entry)
                        log_entries.append(parsed_entry)
    except FileNotFoundError:
        print(f"{Fore.RED}Error: File {file_path} not found.{Style.RESET_ALL}")
    except Exception as e:
        print(f"{Fore.RED}Error: {e}{Style.RESET_ALL}")
    return log_entries

# Analyze multiple log files
def analyze_multiple_logs(file_paths, only_anomalies=False, start_date=None, end_date=None):
    all_log_entries = []
    for file_path in file_paths:
        log_entries = analyze_log(file_path, only_anomalies, start_date, end_date)
        all_log_entries.extend(log_entries)
    return all_log_entries

# Function to display a loading bar
def print_loading_bar(iteration, total, prefix='', suffix='', decimals=1, length=50, fill='█'):
    percent = ("{0:." + str(decimals) + "f}").format(100 * (iteration / float(total)))
    filled_length = int(length * iteration // total)
    bar = fill * filled_length + '-' * (length - filled_length)
    print(f'\r{prefix} |{bar}| {percent}% {suffix}', end='\r')
    if iteration == total:
        print()
        print('\r' + ' ' * (len(prefix) + length + len(suffix) + 10), end='\r')

# Analyze log file
def analyze_log(file_path, only_anomalies=False, start_date=None, end_date=None):
    if not os.path.exists(file_path):
        raise FileNotFoundError(f"File {file_path} not found.")

    log_entries = []
    try:
        with open(file_path, 'r') as file:
            lines = file.readlines()
            total_lines = len(lines)
            for i, line in enumerate(lines):
                print_loading_bar(i + 1, total_lines, prefix='Processing:', suffix='Complete', length=50)
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
    except Exception as e:
        print(f"{Fore.RED}Error: {e}{Style.RESET_ALL}")

    if only_anomalies:
        log_entries = [entry for entry in log_entries if entry['anomalies']]

    return log_entries

# Generate statistics
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

# Display log entries
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

# Display statistics
def display_statistics(stats):
    output = []
    output.append(Fore.GREEN + "\n=== Statistics ===" + Style.RESET_ALL)
    output.append(f"Total Requests: {Fore.YELLOW}{stats['total_requests']}{Style.RESET_ALL}")
    output.append(Fore.GREEN + "\nTop 5 IPs:" + Style.RESET_ALL)
    for ip, count in stats['ip_counter'].most_common(5):
        output.append(f"  {Fore.CYAN}{ip}{Style.RESET_ALL}: {Fore.YELLOW}{count}{Style.RESET_ALL} requests")
    output.append(Fore.GREEN + "\nHTTP Methods:" + Style.RESET_ALL)
    for method, count in stats['method_counter'].items():
        output.append(f"  {Fore.CYAN}{method}{Style.RESET_ALL}: {Fore.YELLOW}{count}{Style.RESET_ALL}")
    output.append(Fore.GREEN + "\nHTTP Status Codes:" + Style.RESET_ALL)
    for status, count in stats['status_counter'].items():
        output.append(f"  {Fore.CYAN}{status}{Style.RESET_ALL}: {Fore.YELLOW}{count}{Style.RESET_ALL}")
    
    return "\n".join(output)

# Generate report of suspicious IPs
def generate_suspicious_ip_report(log_entries):
    suspicious_ips = {}
    suspicious_patterns = {
        'Directory traversal': re.compile(r'(\.\./|\.\.\\)'),
        'SQL injection': re.compile(r'(\b(?:SELECT|INSERT|UPDATE|DELETE|DROP|UNION|--|#)\b)', re.IGNORECASE),
        'XSS': re.compile(r'(\b(?:<script>|</script>|javascript:|onload=|onerror=)\b)', re.IGNORECASE),
        'Sensitive file access': re.compile(r'(\b(?:admin|root|config|passwd|shadow)\b)', re.IGNORECASE),
        'File access': re.compile(r'\.sqlite|\.log|\.db|\.pdf|\.sql', re.IGNORECASE),
        'Brute force': re.compile(r'login|signin|password|admin', re.IGNORECASE)
    }

    for entry in log_entries:
        for activity, pattern in suspicious_patterns.items():
            if pattern.search(entry['url']):
                if entry['ip'] not in suspicious_ips:
                    suspicious_ips[entry['ip']] = {'count': 0, 'activities': set()}
                suspicious_ips[entry['ip']]['count'] += 1
                suspicious_ips[entry['ip']]['activities'].add(activity)

    # Filter out IPs 
    for ip, details in list(suspicious_ips.items()):
        if 'Brute force' in details['activities'] and details['count'] < 10:
            details['activities'].remove('Brute force')
            if not details['activities']:
                del suspicious_ips[ip]

    table = PrettyTable()
    table.field_names = ["IP", "Suspicious Activity Count", "Activities", "Threat Level"]
    sorted_ips = sorted(suspicious_ips.items(), key=lambda x: (-len(x[1]['activities']), -x[1]['count']))
    for ip, details in sorted_ips:
        activity_count = len(details['activities'])
        if activity_count > 5:
            threat_level = "High"
        elif activity_count > 2:
            threat_level = "Medium"
        else:
            threat_level = "Low"
        activities = ", ".join(details['activities'])
        table.add_row([ip, details['count'], activities, threat_level])

    return table

# Main function
def main():
    parser = argparse.ArgumentParser(
        description=Fore.GREEN + r"""
    __                                  __                     
   / /___  ____ _    ____ _____  ____ _/ /_  ______  ___  _____
  / / __ \/ __ `/   / __ `/ __ \/ __ `/ / / / /_  / / _ \/ ___/
 / / /_/ / /_/ /   / /_/ / / / / /_/ / / /_/ / / /_/  __/ /    
/_/\____/\__, /____\__,_/_/ /_/\__,_/_/\__, / /___/\___/_/     
        /____/_____/                  /____/  """ + Fore.RED + "@codewithwan" + Fore.GREEN + r"""     
        """ + Style.RESET_ALL,
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
        help="Search for single or multiple keywords (URL, status, etc.). Example: --find pdf , --find sql,200"
    )
    parser.add_argument(
        "--regex-search", 
        help="Search logs using a regex pattern. Example: --regex-search 'admin'"
    )
    parser.add_argument(
        "--detect", 
        choices=['bruteforce', 'fileaccess'], 
        help="Detect specific attack patterns. Example: --detect bruteforce"
    )
    parser.add_argument(
        "--report", 
        action="store_true", 
        help="Generate a summary report of suspicious IPs.\nExample: --report"
    )
    parser.add_argument(
        "--multi-log", 
        nargs='+', 
        help="Analyze multiple log files. Example: --multi-log file1.log file2.log"
    )
    parser.add_argument(
        "-o", "--output", 
        help="Output file to save the result. If not provided, the result is displayed in the terminal.\nExample: -o output.txt"
    )
    args = parser.parse_args()

    start_date = datetime.strptime(args.start_date, '%Y-%m-%d') if args.start_date else None
    end_date = datetime.strptime(args.end_date, '%Y-%m-%d') if args.end_date else None

    try:
        if args.multi_log:
            log_entries = analyze_multiple_logs(args.multi_log, args.only_anomalies, start_date, end_date)
        else:
            log_entries = analyze_log(args.file, args.only_anomalies, start_date, end_date)

        if args.find:
            log_entries = find_in_logs(log_entries, args.find)

        if args.regex_search:
            log_entries = advanced_regex_search(log_entries, args.regex_search)

        if args.detect:
            attack_stats, url_stats = detect_attack_patterns(log_entries, args.detect)
            table = PrettyTable()
            table.field_names = ["IP", "Attempts"]
            for ip, count in attack_stats.items():
                table.add_row([ip, count])
            
            url_table = PrettyTable()
            url_table.field_names = ["URL", "Attempts"]
            for url, count in url_stats.most_common(5):
                url_table.add_row([url, count])
            
            result = f"{Fore.RED}{args.detect.capitalize()} Attempts: {sum(attack_stats.values())}{Style.RESET_ALL}\n{table}\n"
            result += f"\n{Fore.RED}Top Targeted URLs:{Style.RESET_ALL}\n{url_table}"
        elif args.stats:
            stats = generate_statistics(log_entries)
            result = display_statistics(stats)
        elif args.report:
            result = generate_suspicious_ip_report(log_entries)
        else:
            result = display_log_entries(log_entries)

        if args.output:
            with open(args.output, 'w') as output_file:
                output_file.write(str(result))
            print(f"Output saved to {args.output}")
        else:
            print(result)

    except FileNotFoundError as e:
        print(f"{Fore.RED}Error: {e}{Style.RESET_ALL}")
    except Exception as e:
        print(f"{Fore.RED}Unexpected error: {e}{Style.RESET_ALL}")

if __name__ == "__main__":
    main()
