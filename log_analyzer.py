import argparse
import os
import re
from collections import Counter
from prettytable import PrettyTable
from datetime import datetime
from colorama import Fore, Style, init
from concurrent.futures import ThreadPoolExecutor

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
    highlighted_entries = []
    for entry in log_entries:
        if all(term in entry['url'] or term in entry['status'] or term in entry['ip'] or term in entry['method'] for term in terms):
            highlighted_entry = entry.copy()
            for term in terms:
                highlighted_entry['url'] = re.sub(f"({term})", f"{Fore.RED}{Style.BRIGHT}\\1{Style.RESET_ALL}", highlighted_entry['url'])
                highlighted_entry['status'] = re.sub(f"({term})", f"{Fore.RED}{Style.BRIGHT}\\1{Style.RESET_ALL}", highlighted_entry['status'])
                highlighted_entry['ip'] = re.sub(f"({term})", f"{Fore.RED}{Style.BRIGHT}\\1{Style.RESET_ALL}", highlighted_entry['ip'])
                highlighted_entry['method'] = re.sub(f"({term})", f"{Fore.RED}{Style.BRIGHT}\\1{Style.RESET_ALL}", highlighted_entry['method'])
            highlighted_entries.append(highlighted_entry)
    return highlighted_entries

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
        'largefile': re.compile(r'\.zip|\.tar|\.gz|\.rar', re.IGNORECASE),
        'directorytraversal': re.compile(r'(\.\./|\.\.\\)'),
        'sqli': re.compile(r'(\b(?:SELECT|INSERT|UPDATE|DELETE|DROP|UNION|--|#)\b)', re.IGNORECASE),
        'xss': re.compile(r'(\b(?:<script>|</script>|javascript:|onload=|onerror)\b)', re.IGNORECASE),
        'forbiddenaccess': re.compile(r'403'),
        'ddos': re.compile(r'(\b(?:GET|POST)\b)', re.IGNORECASE),
        'malware': re.compile(r'(\b(?:virus|malware|trojan|worm|spyware|ransomware)\b)', re.IGNORECASE),
        'recentattack': re.compile(r'(\b(?:exploit|vulnerability|zero-day|cve)\b)', re.IGNORECASE)
    }
    if attack_type not in attack_patterns:
        raise ValueError(f"Unknown attack type: {attack_type}")

    attack_stats = Counter()
    url_stats = Counter()
    pattern = attack_patterns[attack_type]
    for entry in log_entries:
        if pattern.search(entry['url']) or (attack_type == 'forbiddenaccess' and entry['status'] == '403'):
            attack_stats[entry['ip']] += 1
            url_stats[entry['url']] += 1

    if attack_type == 'bruteforce':
        attack_stats = {ip: count for ip, count in attack_stats.items() if count > 10}

    sorted_attack_stats = dict(sorted(attack_stats.items(), key=lambda item: item[1], reverse=True))
    return sorted_attack_stats, url_stats

# Analyze large log file with threading and loading bar
def analyze_large_log(file_path, chunk_size=1024):
    log_entries = []
    try:
        with open(file_path, 'r') as file:
            file_size = os.path.getsize(file_path)
            read_size = 0
            while chunk := file.read(chunk_size):
                read_size += len(chunk)
                print_loading_bar(read_size, file_size, prefix='Processing:', suffix='Complete', length=50)
                lines = chunk.splitlines()
                with ThreadPoolExecutor() as executor:
                    results = executor.map(parse_and_sanitize_log_entry, lines)
                    log_entries.extend(filter(None, results))
    except FileNotFoundError:
        print(f"{Fore.RED}Error: File {file_path} not found.{Style.RESET_ALL}")
    except Exception as e:
        print(f"{Fore.RED}Error: {e}{Style.RESET_ALL}")
    return log_entries

# Custom function to parse and sanitize log entry
def parse_and_sanitize_log_entry(line):
    parsed_entry = parse_log_entry(line)
    if parsed_entry:
        return sanitize_log_entry(parsed_entry)
    return None

# Check if the file is a valid log file
def is_valid_log_file(file_path):
    return file_path.endswith('.log')

# Analyze log file
def analyze_log(file_path, only_anomalies=False, start_date=None, end_date=None):
    if not is_valid_log_file(file_path):
        raise ValueError(f"Invalid file format: {file_path}. Only .log files are supported.")
    if not os.path.exists(file_path):
        raise FileNotFoundError(f"File {file_path} not found.")

    log_entries = []
    try:
        with open(file_path, 'r') as file:
            lines = file.readlines()
            total_lines = len(lines)
            with ThreadPoolExecutor() as executor:
                results = executor.map(process_log_line, lines, [start_date]*total_lines, [end_date]*total_lines)
                for i, result in enumerate(results):
                    print_loading_bar(i + 1, total_lines, prefix='Analyzing File:', suffix='Complete', length=50)
                    if result:
                        log_entries.append(result)
    except Exception as e:
        print(f"{Fore.RED}Error: {e}{Style.RESET_ALL}")

    if only_anomalies:
        log_entries = [entry for entry in log_entries if entry['anomalies']]

    return log_entries

# Process log line
def process_log_line(line, start_date, end_date):
    parsed_entry = parse_log_entry(line)
    if parsed_entry:
        parsed_entry = sanitize_log_entry(parsed_entry)
        entry_date = datetime.strptime(parsed_entry['date'], '%d/%b/%Y:%H:%M:%S %z')
        if start_date and entry_date < start_date:
            return None
        if end_date and entry_date > end_date:
            return None
        anomalies, rating = detect_anomalies(parsed_entry)
        parsed_entry['anomalies'] = anomalies
        parsed_entry['rating'] = rating
        return parsed_entry
    return None

# Analyze multiple log files
def analyze_multiple_logs(file_paths, only_anomalies=False, start_date=None, end_date=None):
    all_log_entries = []
    for file_path in file_paths:
        if not is_valid_log_file(file_path):
            print(f"{Fore.RED}Skipping invalid file format: {file_path}. Only .log files are supported.{Style.RESET_ALL}")
            continue
        log_entries = analyze_log(file_path, only_anomalies, start_date, end_date)
        all_log_entries.extend(log_entries)
    return all_log_entries

# Function to display a loading bar
def print_loading_bar(iteration, total, prefix='', suffix='', decimals=1, length=50, fill='█'):
    percent = ("{0:." + str(decimals) + "f}").format(100 * (iteration / float(total)))
    filled_length = int(length * iteration // total)
    bar = Fore.GREEN + fill * filled_length + Fore.RED + '-' * (length - filled_length) + Style.RESET_ALL
    print(f'\r{prefix} |{bar}| {percent}% {suffix}', end='\r')
    if iteration == total:
        print()
        print('\r' + ' ' * (len(prefix) + length + len(suffix) + 10), end='\r')

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
    output.append(Fore.GREEN + "\n====== Statistics ======" + Style.RESET_ALL)
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
        'XSS': re.compile(r'(\b(?:<script>|</script>|javascript:|onload=|onerror)\b)', re.IGNORECASE),
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

# Detect User-Agent anomalies
def detect_user_agent_anomalies(log_entries):
    suspicious_user_agents = {}
    suspicious_patterns = {
        'Suspicious User-Agent': re.compile(r'(curl|wget|python-requests|libwww-perl|nikto|sqlmap)', re.IGNORECASE)
    }

    for entry in log_entries:
        for activity, pattern in suspicious_patterns.items():
            if pattern.search(entry['user_agent']):
                if entry['ip'] not in suspicious_user_agents:
                    suspicious_user_agents[entry['ip']] = {'count': 0, 'user_agents': set()}
                suspicious_user_agents[entry['ip']]['count'] += 1
                suspicious_user_agents[entry['ip']]['user_agents'].add(entry['user_agent'])

    table = PrettyTable()
    table.field_names = ["IP", "Suspicious User-Agent Count", "User-Agents"]
    sorted_ips = sorted(suspicious_user_agents.items(), key=lambda x: (-x[1]['count']))
    for ip, details in sorted_ips:
        user_agents = ", ".join(details['user_agents'])
        table.add_row([ip, details['count'], user_agents])

    return table

# Save output to file
def save_output_to_file(output, file_name):
    output_dir = 'output'
    if not os.path.exists(output_dir):
        os.makedirs(output_dir)
    file_path = os.path.join(output_dir, file_name)
    with open(file_path, 'w') as output_file:
        output_file.write(re.sub(r'\x1b\[[0-9;]*m', '', str(output)))
    print(f"{Fore.GREEN}\nOutput saved to {file_path}\n{Style.RESET_ALL}")

# Display attack graph
def display_attack_graph(attack_stats):
    max_ip_length = max(len(ip) for ip in attack_stats.keys())
    max_count = max(attack_stats.values())
    scale = 50 / max_count

    print(Fore.GREEN + "\n====== Attack Graph ======" + Style.RESET_ALL)
    for ip, count in attack_stats.items():
        bar_length = int(count * scale)
        if count > max_count * 0.75:
            bar_color = Fore.RED
        elif count > max_count * 0.5:
            bar_color = Fore.YELLOW
        else:
            bar_color = Fore.GREEN
        bar = bar_color + '█' * bar_length + Style.RESET_ALL
        print(f"{ip.ljust(max_ip_length)} | {bar} {count}")
    print("\n")
    
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
        "-f", "--file", 
        required=True, 
        help="Path to the log file (required).\nExample: --file access.log"
    )
    parser.add_argument(
        "-a", "--only-anomalies", 
        action="store_true", 
        help="Display only entries with anomalies.\nExample: --only-anomalies"
    )
    parser.add_argument(
        "-s", "--stats", 
        action="store_true", 
        help="Display statistics of the log file.\nExample: --stats"
    )
    parser.add_argument(
        "-sd", "--start-date", 
        help="Filter logs starting from this date (inclusive). Format: YYYY-MM-DD\nExample: --start-date 2023-01-01"
    )
    parser.add_argument(
        "-ed", "--end-date", 
        help="Filter logs up to this date (inclusive). Format: YYYY-MM-DD\nExample: --end-date 2023-12-31"
    )
    parser.add_argument(
        "-fi", "--find", 
        help="Search for single or multiple keywords (URL, status, etc.). Example: --find pdf , --find sql,200"
    )
    parser.add_argument(
        "-rs", "--regex-search", 
        help="Search logs using a regex pattern. Example: --regex-search 'admin'"
    )
    parser.add_argument(
        "--detect", 
        choices=['bruteforce', 'fileaccess', 'largefile', 'directorytraversal', 'sqli', 'xss', 'forbiddenaccess', 'ddos', 'malware', 'recentattack'], 
        help="Detect specific attack patterns. Example: --detect bruteforce"
    )
    parser.add_argument(
        "--graph", 
        action="store_true", 
        help="Display a graphical representation of the attack patterns. Example: --detect bruteforce --graph"
    )
    parser.add_argument(
        "-r", "--report", 
        action="store_true", 
        help="Generate a summary report of suspicious IPs.\nExample: --report"
    )
    parser.add_argument(
        "-ml", "--multi-log", 
        nargs='+', 
        help="Analyze multiple log files. Example: --multi-log file1.log file2.log"
    )
    parser.add_argument(
        "-ua", "--user-agent-report", 
        action="store_true", 
        help="Generate a report of suspicious User-Agents.\nExample: --user-agent-report"
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
            if not is_valid_log_file(args.file):
                raise ValueError(f"Invalid file format: {args.file}. Only .log files are supported.")
            log_entries = analyze_log(args.file, args.only_anomalies, start_date, end_date)

        if args.find:
            log_entries = find_in_logs(log_entries, args.find)

        if args.regex_search:
            log_entries = advanced_regex_search(log_entries, args.regex_search)

        if not log_entries:
            result = f"{Fore.RED}\nNo entries found matching the criteria.\n{Style.RESET_ALL}"
        elif args.detect:
            attack_stats, url_stats = detect_attack_patterns(log_entries, args.detect)
            table = PrettyTable()
            table.field_names = ["IP", "Attempts"]
            for ip, count in attack_stats.items():
                table.add_row([ip, count])
            
            url_table = PrettyTable()
            url_table.field_names = ["URL", "Attempts"]
            for url, count in url_stats.most_common(10):
                url_table.add_row([url, count])
            
            result = f"{Fore.RED}{args.detect.capitalize()} Attempts: {sum(attack_stats.values())}{Style.RESET_ALL}\n{table}\n"
            result += f"\n{Fore.RED}Top Targeted URLs:{Style.RESET_ALL}\n{url_table}"
            
            if args.graph:
                display_attack_graph(attack_stats)
        elif args.stats:
            stats = generate_statistics(log_entries)
            result = display_statistics(stats)
        elif args.report:
            result = generate_suspicious_ip_report(log_entries)
        elif args.user_agent_report:
            result = detect_user_agent_anomalies(log_entries)
        else:
            result = display_log_entries(log_entries)

        if args.output:
            save_output_to_file(result, args.output)
        else:
            print(result)

    except FileNotFoundError as e:
        print(f"{Fore.RED}\nError: {e}\n{Style.RESET_ALL}")
    except ValueError as e:
        print(f"{Fore.RED}\nError: {e}\n{Style.RESET_ALL}")
    except Exception as e:
        print(f"{Fore.RED}\nUnexpected error: {e}{Style.RESET_ALL}")

if __name__ == "__main__":
    main()
