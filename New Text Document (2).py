import re
import csv
import json
from collections import Counter
from bs4 import BeautifulSoup

# File paths
access_log_path = 'access_log.txt'
url_status_report_path = 'url_status_report.txt'
malware_candidates_path = 'malware_candidates.csv'
alert_json_path = 'alert.json'
summary_report_path = 'summary_report.json'
thread_feed_path = 'thread_feed.html'

# Regex to extract URLs and status codes
url_status_regex = re.compile(r'\"[A-Z]+ (.*?) HTTP/\d\.\d\" (\d{3})')

# Step 1: Extract URLs and status codes
url_status_data = []
with open(access_log_path, 'r') as log_file:
    for line in log_file:
        match = url_status_regex.search(line)
        if match:
            url, status_code = match.groups()
            url_status_data.append((url, status_code))

# Step 2: Filter 404 URLs and count occurrences
status_counter = Counter()
not_found_urls = Counter()
for url, status_code in url_status_data:
    status_counter[(url, status_code)] += 1
    if status_code == '404':
        not_found_urls[url] += 1

# Step 3: Save URL and status code report
with open(url_status_report_path, 'w') as report_file:
    for (url, status_code), count in status_counter.items():
        report_file.write(f"{url} {status_code} {count}\n")

# Step 4: Save 404 URLs to CSV
with open(malware_candidates_path, 'w', newline='') as csv_file:
    writer = csv.writer(csv_file)
    writer.writerow(['URL', '404 Count'])
    for url, count in not_found_urls.items():
        writer.writerow([url, count])

# Step 5: Parse threat feed for blacklisted domains
with open(thread_feed_path, 'r') as feed_file:
    soup = BeautifulSoup(feed_file, 'html.parser')

blacklisted_domains = set()
for link in soup.find_all('a'):
    blacklisted_domains.add(link.get_text(strip=True))

# Step 6: Match URLs against blacklisted domains
blacklist_matches = {}
for url, count in not_found_urls.items():
    for domain in blacklisted_domains:
        if domain in url:
            blacklist_matches[url] = {'domain': domain, 'count': count}

# Step 7: Save alert JSON
with open(alert_json_path, 'w') as alert_file:
    json.dump(blacklist_matches, alert_file, indent=4)

# Step 8: Save summary report JSON
summary_report = {
    'total_urls': len(status_counter),
    'total_404_urls': len(not_found_urls),
    'total_blacklist_matches': len(blacklist_matches),
    'blacklisted_urls': list(blacklist_matches.keys())
}

with open(summary_report_path, 'w') as summary_file:
    json.dump(summary_report, summary_file, indent=4)

print("Analysis completed. Output files generated:")
print(f"1. {url_status_report_path}")
print(f"2. {malware_candidates_path}")
print(f"3. {alert_json_path}")
print(f"4. {summary_report_path}")
