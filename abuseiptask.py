import requests
 
import re
 
import sys
 
API_KEY = ''  # Replace with your AbuseIPDB API key
 
API_URL = 'https://api.abuseipdb.com/api/v2/check'
 
HEADERS = {
 
    'Accept': 'application/json',
 
    'Key': API_KEY
 
}
 
def check_ip_reputation(ip):
 
    try:
 
        response = requests.get(API_URL, headers=HEADERS, params={'ipAddress': ip})
 
        if response.status_code != 200:
 
            print(f"[-] Error checking {ip}: {response.json().get('errors', [{'detail': 'Unknown error'}])[0]['detail']}")
 
            return
 
        data = response.json()['data']
 
        abuse_score = data.get('abuseConfidenceScore', 'N/A')
 
        country = data.get('countryCode', 'N/A')
 
        last_report = data.get('lastReportedAt', 'N/A')
 
        print(f"[+] IP: {ip}")
 
        print(f"    ➤ Abuse Score: {abuse_score}")
 
        print(f"    ➤ Country: {country}")
 
        print(f"    ➤ Last Reported: {last_report}\n")
 
    except requests.exceptions.RequestException as e:
 
        print(f"[-] Request error for {ip}: {e}")
 
    except ValueError:
 
        print(f"[-] Failed to decode JSON response for {ip}")
 
    except Exception as e:
 
        print(f"[-] Unexpected error for {ip}: {str(e)}")
 
def extract_ips_from_file(file_path):
 
    try:
 
        with open(file_path, 'r') as f:
 
            content = f.read()
 
            ip_pattern = re.compile(r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b')
 
            return ip_pattern.findall(content)
 
    except FileNotFoundError:
 
        print(f"[-] File not found: {file_path}")
 
        return []
 
    except Exception as e:
 
        print(f"[-] Error reading file: {str(e)}")
 
        return []
 
def main():
 
    print("=== AbuseIPDB Reputation Checker ===")
 
    print("1. Check individual IP(s)")
 
    print("2. Extract and check IPs from a text file")
 
    try:
 
        choice = input("Choose an option (1 or 2): ").strip()
 
    except EOFError:
 
        print("[-] No input provided. Exiting.")
 
        sys.exit(1)
 
    if choice == '1':
 
        try:
 
            ip_input = input("Enter IPs separated by commas: ").strip()
 
        except EOFError:
 
            print("[-] No input provided. Exiting.")
 
            sys.exit(1)
 
        ips = [ip.strip() for ip in ip_input.split(',')]
 
        for ip in ips:
 
            if re.fullmatch(r'(?:[0-9]{1,3}\.){3}[0-9]{1,3}', ip):
 
                check_ip_reputation(ip)
 
            else:
 
                print(f"[-] Invalid IP format: {ip}")
 
    elif choice == '2':
 
        try:
 
            file_path = input("Enter the path to the text file: ").strip()
 
        except EOFError:
 
            print("[-] No input provided. Exiting.")
 
            sys.exit(1)
 
        ips = extract_ips_from_file(file_path)
 
        if ips:
 
            print(f"[+] Found {len(ips)} IP(s) in file. Checking reputation...\n")
 
            for ip in ips:
 
                check_ip_reputation(ip)
 
        else:
 
            print("[-] No valid IPs found in file or unable to read file.")
 
    else:
 
        print("[-] Invalid option selected. Exiting.")
 
        sys.exit(1)
 
if __name__ == "__main__":
 
    main()
 