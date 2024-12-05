import re
from collections import defaultdict, deque
from datetime import datetime, timedelta
import argparse
import mmap
from concurrent.futures import ProcessPoolExecutor
import geoip2.database

# Compile regex pattern once
LOG_PATTERN = re.compile(r'(\S+) - - \[(.*?)\] "(.*?)" (\d+) (\d+)')

# Path to the GeoLite2 database (adjust as needed)
GEOIP_DB_PATH = "/home/ajcreec/GeoLite2-City_20241203/GeoLite2-City.mmdb"

def parse_log_line(line):
    match = LOG_PATTERN.match(line)
    if match:
        ip, timestamp, request, status, size = match.groups()
        return ip, timestamp, request, int(status), int(size)
    return None

def process_chunk(chunk, time_window_minutes, threshold, geoip_db_path):
    failed_attempts = defaultdict(lambda: deque())
    suspicious_ips = defaultdict(list)
    time_window = timedelta(minutes=time_window_minutes)

    with geoip2.database.Reader(geoip_db_path) as geoip_reader:
        for line_number, line in chunk:
            parsed = parse_log_line(line)
            if parsed:
                ip, timestamp, request, status, _ = parsed
                if '/login' in request and status == 401:
                    time = datetime.strptime(timestamp, '%d/%b/%Y:%H:%M:%S %z')
                    attempts = failed_attempts[ip]
                    attempts.append((line_number, time))
                    
                    # Remove attempts outside the time window
                    while attempts and time - attempts[0][1] > time_window:
                        attempts.popleft()
                    
                    if len(attempts) >= threshold:
                        try:
                            country = geoip_reader.city(ip).country.name
                        except Exception:
                            country = "Unknown"
                        
                        suspicious_ips[ip].append({
                            "line_number": line_number,
                            "datetime": time,
                            "country": country,
                        })

    return suspicious_ips

def filter_failed_logins_parallel(log_file, time_window_minutes, threshold):
    chunk_size = 150  # Number of lines per chunk

    def chunk_reader(file, size):
        chunk = []
        for line_number, line in enumerate(file, start=1):
            chunk.append((line_number, line))
            if len(chunk) >= size:
                yield chunk
                chunk = []
        if chunk:
            yield chunk

    suspicious_ips = defaultdict(list)
    with open(log_file, 'r') as f:
        with ProcessPoolExecutor(max_workers=2) as executor:  # Limit to 2 workers
            futures = [
                executor.submit(process_chunk, chunk, time_window_minutes, threshold, GEOIP_DB_PATH)
                for chunk in chunk_reader(f, chunk_size)
            ]

            for future in futures:
                result = future.result()
                for ip, details in result.items():
                    suspicious_ips[ip].extend(details)

    return suspicious_ips

def query(search_string, log_file):
    matching_lines = []
    try:
        with open(log_file, 'r') as file:
            with mmap.mmap(file.fileno(), length=0, access=mmap.ACCESS_READ) as mm:
                for line_number, line in enumerate(iter(mm.readline, b''), 1):
                    line = line.decode('utf-8')
                    if re.search(search_string, line, re.IGNORECASE):
                        matching_lines.append((line_number, line.strip()))
        return matching_lines
    except FileNotFoundError:
        print(f"Error: The file '{log_file}' was not found.")
        return []
    except IOError:
        print(f"Error: Unable to read the file '{log_file}'.")
        return []
    except Exception as e:
        print(f"An unexpected error occurred: {str(e)}")
        return []

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Log Analysis Tool")
    parser.add_argument("log_file", help="Path to the log file")
    parser.add_argument("--time_window", type=int, default=5, 
                        help="Time window in minutes for failed logins (default: 5)")
    parser.add_argument("--threshold", type=int, default=10, 
                        help="Threshold for suspicious activity (default: 10)")
    parser.add_argument("--search", type=str, default=None, 
                        help="String to search in the log file")

    args = parser.parse_args()

    # Run the filter for suspicious IPs
    print("Analyzing for suspicious IPs...")
    suspicious_ips = filter_failed_logins_parallel(args.log_file, args.time_window, args.threshold)

    if suspicious_ips:
        print("Suspicious IP addresses with repeated failed login attempts:")
        for ip, details in suspicious_ips.items():
            print(f"\nIP: {ip}")
            for detail in details:
                print(f"  - Line: {detail['line_number']}, Date/Time: {detail['datetime']}, Country: {detail['country']}")
    else:
        print("No suspicious activity detected.")

    # Search the log file if a search string is provided
    if args.search:
        print(f"\nSearching for '{args.search}' in {args.log_file}...")
        results = query(args.search, args.log_file)
        if results:
            print(f"Found {len(results)} matching line(s):")
            for line_number, line in results:
                print(f"Line {line_number}: {line}")
        else:
            print(f"No matches found for '{args.search}' in {args.log_file}'.")
