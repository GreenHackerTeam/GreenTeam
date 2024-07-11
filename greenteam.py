import socket
import requests
from bs4 import BeautifulSoup
from datetime import datetime
import platform
import socialscan

GREEN = '\033[92m'
RESET = '\033[0m'
RED   = '\033[31m'

def print_green(text):
    print(f"{GREEN}{text}{RESET}")

def print_red(text):
    print(f"{GREEN}{text}{RESET}")

def port_scanner(target):
    print_green(f"Starting port scanning for {target}...")
    print_green("-" * 60)
    
    try:
        for port in range(1, 1025):
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            socket.setdefaulttimeout(1)
            
            result = sock.connect_ex((target, port))
            if result == 0:
                print_green(f"Port {port}: Open")
            sock.close()
    
    except KeyboardInterrupt:
        print_red("\nExiting the scan.")
        exit()
    
    except socket.gaierror:
        print_red("The hostname cannot be resolved. Exit the scan.")
        exit()
    
    except socket.error:
        print_red("Unable to connect to the server.")
        exit()

    print_green("-" * 60)
    print_green(f"Scanning ports for {target} completed.")
    print_green("-" * 60)

def vulnerability_scanner(target_url):
    sql_payloads = ["' OR '1'='1", "'; DROP TABLE users; --"]
    xss_payloads = ["<script>alert('XSS')</script>", "<img src='x' onerror='alert(1)'>"]
    
    def test_sql_injection(url):
        for payload in sql_payloads:
            r = requests.get(url + payload)
            if "syntax error" in r.text or "mysql" in r.text:
                print_green(f"SQL Injection vulnerability found with payload: {payload}")
                return True
        return False
    
    def test_xss(url):
        for payload in xss_payloads:
            r = requests.get(url + payload)
            if payload in r.text:
                print_green(f"XSS vulnerability found with payload: {payload}")
                return True
        return False
    
    def test_csrf(url):
        r = requests.get(url)
        soup = BeautifulSoup(r.text, 'html.parser')
        forms = soup.find_all('form')
        
        for form in forms:
            inputs = form.find_all('input')
            has_csrf_token = False
            
            for input_tag in inputs:
                if 'csrf' in input_tag.get('name', '').lower():
                    has_csrf_token = True
                    break
            
            if not has_csrf_token:
                print_red(f"The form on the page {url} does not contain CSRF tokens")
                return True
        return False
    
    def check_vulnerabilities(target_url):
        base_url = "https://services.nvd.nist.gov/rest/json/cves/1.0"
        parameters = {
            "keyword": target_url,
            "resultsPerPage": 10,
            "pubStartDate": "2023-01-01T00:00:00:000 UTC-00:00",
            "orderBy": "publishedDate:desc"
        }
        
        try:
            response = requests.get(base_url, params=parameters)
            data = response.json()
            
            if data.get("result", {}).get("totalResults") > 0:
                print_green("The following vulnerabilities were found in the components:")
                for item in data["result"]["CVE_Items"]:
                    cve_id = item["cve"]["CVE_data_meta"]["ID"]
                    description = item["cve"]["description"]["description_data"][0]["value"]
                    print_green(f"- CVE ID: {cve_id}")
                    print_green(f"  description: {description}")
                return True
            else:
                print_red("No known vulnerabilities were found in the components.")
                return False
        
        except Exception as e:
            print_red(f"Error checking vulnerabilities: {str(e)}")
            return False
    
    print_green("Vulnerability check...")
    sql_injection_found = test_sql_injection(target_url)
    xss_found = test_xss(target_url)
    csrf_found = test_csrf(target_url)
    vulnerabilities_found = check_vulnerabilities(target_url)
    
    if not sql_injection_found:
        print_red("No SQL injections found.")
    if not xss_found:
        print_red("XSS not found.")
    if not csrf_found:
        print_red("All forms contain CSRF tokens.")
    if not vulnerabilities_found:
        print_red("No known vulnerabilities were found in the components.")
    print_green("-" * 60)

def hidden_directory_scanner(base_url):
    common_paths = [
        "/admin/",
        "/administrator/",
        "/login/",
        "/secret/",
        "/hidden/",
        "/.git/",
        "/.svn/",
        "/.htaccess",
        "/robots.txt",
        "/sitemap.xml",
    ]
    
    print_green("We start scanning hidden directories and files...")
    print_green("-" * 60)
    
    for path in common_paths:
        url = base_url + path
        try:
            response = requests.get(url)
            if response.status_code == 200:
                print_green(f"A hidden resource has been found: {url}")
            elif response.status_code == 403:
                print_red(f"Access to the resource is prohibited: {url}")
            elif response.status_code == 404:
                print_red(f"The resource was not found: {url}")
            else:
                print_red(f"Unknown status of the response code {response.status_code} for the resource: {url}")
        except requests.exceptions.RequestException as e:
            print(f"Request error {url}: {e}")
    
    print_green("-" * 60)
    print_green("Scanning of hidden directories and files is completed.")
    print_green("-" * 60)

def gather_system_info(target):
    print_green(f"Collecting information about the system {target}...")
    print_green("-" * 60)
    
    try:
        remote_ip = socket.gethostbyname(target)
        print_green(f"IP-address: {remote_ip}")
        
        sys_info = platform.uname()
        print_green(f"The operating system: {sys_info.system} {sys_info.release}")
        
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        socket.setdefaulttimeout(1)
        result = sock.connect_ex((target, 80))
        
        if result == 0:
            print_green("The host is available and responds to port 80")
        else:
            print_red("The host is unavailable on port 80")
        
        sock.close()
    
    except socket.error:
        print_red(f"Could not get information about {target}")
    
    except KeyboardInterrupt:
        print_red("\nExit from information collection.")
        exit()

    print_green("-" * 60)
    print_green(f"Collecting information about the system {target} completed.")
    print_green("-" * 60)

def os_intelligence(target):
    print_green(f"OSINT intelligence for {target}...")
    print_green("-" * 60)
    
    try:
        print_red("This feature is not currently implemented..")
        
    except Exception as e:
        print_red(f"An error occurred during OSINT exploration: {str(e)}")
    
    print_green("-" * 60)
    print_green(f"OSINT intelligence for {target} completed.")
    print_green("-" * 60)

def ip_geolocation(target_ip):
    print(f"Getting IP location information {target_ip}...")
    print("-" * 60)
    
    try:
        url = f"https://ipinfo.io/{target_ip}/json"
        response = requests.get(url)
        data = response.json()
        
        if 'country' in data:
            print(f"IP: {data.get('ip')}")
            print(f"Country: {data.get('country')}")
            print(f"Region: {data.get('region')}")
            print(f"City: {data.get('city')}")
            print(f"Postal code: {data.get('postal')}")
            print(f"Organization/Provider: {data.get('org')}")
        else:
            print("IP location information is unavailable or not found.")
            print(f"Server response: {response.text}")
        
    except requests.exceptions.RequestException as e:
        print(f"An error occurred when requesting IP location information: {str(e)}")
    
    except Exception as e:
        print(f"An unknown error has occurred: {str(e)}")
    
    print("-" * 60)
    print(f"IP Location Information {target_ip} received.")
    print("-" * 60)

def password_bruteforce(target_url, username, password_list):
    print(f"Brute-forcing passwords for {target_url}...")
    print("-" * 60)
    
    for password in password_list:
        data = {
            'username': username,
            'password': password
        }
        
        try:
            response = requests.post(target_url, data=data)
            
            if "incorrect" not in response.text.lower():  
                print(f"[+] Password found: {password}")
                break
            else:
                print(f"[-] Invalid password: {password}")
        
        except requests.exceptions.RequestException as e:
            print(f"An error occurred while executing the request: {str(e)}")
    
    print("-" * 60)
    print("Password bruteforce is complete.")
    print("-" * 60)

def social_media_analysis(target):
    print(f"Social media analysis for {target}...")
    print("-" * 60)
    
    try:
        results = socialscan.search(target)
        
        if results:
            for result in results:
                print(f"Social network: {result['platform']}")
                print(f"Profile: {result['profile']}")
                print(f"URL: {result['url']}")
                print("-" * 60)
        else:
            print("There are no search results for the specified object.")
    
    except Exception as e:
        print(f"An error occurred while analyzing social networks: {str(e)}")
    
    print(f"Social media analysis for {target} completed.")
    print("-" * 60)

if __name__ == "__main__":
    print_green("""(  ____ \(  ____ )(  ____ \(  ____ \( (    /|  \__   __/(  ____ \(  ___  )(       )
| (    \/| (    )|| (    \/| (    \/|  \  ( |     ) (   | (    \/| (   ) || () () |
| |      | (____)|| (__    | (__    |   \ | |     | |   | (__    | (___) || || || |
| | ____ |     __)|  __)   |  __)   | (\ \) |     | |   |  __)   |  ___  || |(_)| |
| | \_  )| (\ (   | (      | (      | | \   |     | |   | (      | (   ) || |   | |
| (___) || ) \ \__| (____/\| (____/\| )  \  |     | |   | (____/\| )   ( || )   ( |
(_______)|/   \__/(_______/(_______/|/    )_)     )_(   (_______/|/     \||/     \|  """)
    print_green("\n            Select a mode:")
    print_green("\n             1. Port Scanner")
    print_green("             2. Vulnerability Scanner (SQL, XSS, CSRF, component vulnerability check)")
    print_green("             3. Scanner of hidden directories and files")
    print_green("             4. OSINT")
    print_green("             5. Brute-forcing passwords")
    print_green("\n          99. Exit")
    choice = input("\n\033[92mGreenTeam-> ")
    
    if choice == "1":
        target = input("\033[92mEnter the IP address or domain name to scan the ports: ")
        port_scanner(target)
    elif choice == "2":
        target_url = input("\033[92mEnter the URL to check for vulnerabilities: ")
        vulnerability_scanner(target_url)
    elif choice == "3":
        base_url = input("\033[92mEnter the base URL for scanning hidden directories and files: ")
        hidden_directory_scanner(base_url)
    elif choice == "4":
        print_green("\n         Select a mode:")
        print_green("          1. Collecting information about the system")
        print_green("          2. Getting IP location information")
        print_green("          3. Social Media Analysis")
        sub_choice = input("\n\033[92mGreenTeam->OSINT-> ")
        
        if sub_choice == "1":
            target = input("\033[92mEnter the IP address or domain name to collect information about the system: ")
            gather_system_info(target)

        elif sub_choice == '2':
            target_ip = input("\033[92mEnter the IP address to get location information: ")
            ip_geolocation(target_ip)
            
        elif sub_choice == "3":
            target = input("\033[92mEnter the IP address or domain name for social network analysis: ")
            social_media_analysis(target)
            
        else:
            print_red("Wrong choice of method.")

    elif choice == '5':
        target_url = input("\033[92mEnter the URL for brute-forcing passwords: ")
        username = input("\033[92mEnter the user name: ")
        password_file = input("\033[92mEnter the path to the password list file: ")

    elif choice == '99':
        quit()
            
    else:
        print_red("Incorrect mode selection.")
