import os
import subprocess
import time
import logging
import concurrent.futures
import pyfiglet
import json
import re
import argparse
from tqdm import tqdm
from logging.handlers import RotatingFileHandler
import shutil


print("""
***************************************************************
*                                                             *
*                Copyright (c) [2025] [Joel Indra]            *
*                   All rights reserved.                      *
*                                                             *
*    Unauthorized copying, distribution, or modification is   *
*    prohibited without explicit permission.                  *
*                                                             *
*    Author: [Joel Indra]                                     *
*    Feel free to contribute!                                 *
*                                                             *
***************************************************************
""")

    
# Set up logging for better traceability and rotation
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(message)s')
handler = RotatingFileHandler('scan.log', maxBytes=10**6, backupCount=5)
logging.getLogger().addHandler(handler)

# Define color codes for output
MAGENTA = '\033[0;35m'
CYAN = '\033[0;36m'
GREEN = '\033[0;32m'
RED = '\033[0;31m'
YELLOW = '\033[1;33m'

# Function to generate ASCII text using pyfiglet
def ascii_art(text):
    return pyfiglet.figlet_format(text, font="block")

# Validate domain or file input
def validate_input(input_data):
    if not os.path.isfile(input_data) and not re.match(r'^[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$', input_data):
        logging.error(f"{RED}Invalid domain or file path. Please provide a valid input.{RED}")
        return False
    return True

# Function to create necessary directories for the domain
def create_directories(domain):
    directories = [
        "sources", "result", "result/nuclei", "result/wayback", 
        "result/httpx", "result/exploit", "result/js"
    ]
    for dir_name in directories:
        os.makedirs(f"{domain}/{dir_name}", exist_ok=True)
    logging.info(f"{GREEN}Created necessary directories for {domain}{GREEN}")

# Function to delete empty directories
def delete_empty_directories(domain):
    for root, dirs, files in os.walk(domain, topdown=False):
        for dir_name in dirs:
            dir_path = os.path.join(root, dir_name)
            if not os.listdir(dir_path):  # Check if the directory is empty
                try:
                    os.rmdir(dir_path)  # Remove the empty directory
                    logging.info(f"{GREEN}Deleted empty directory: {dir_path}{GREEN}")
                except OSError as e:
                    logging.error(f"{RED}Failed to delete {dir_path}: {e}{RED}")

# Function to run subfinder
def run_subfinder(domain):
    logging.info(f"{GREEN}Running subfinder for {domain}...{GREEN}")
    try:
        subprocess.run(['subfinder', '-d', domain, '-o', f"{domain}/sources/subfinder.txt"], check=True)
        logging.info(f"{GREEN}subfinder completed for {domain}.{GREEN}")
    except subprocess.CalledProcessError:
        logging.error(f"{RED}Error: subfinder failed for {domain}.{RED}")

# Function to run assetfinder
def run_assetfinder(domain):
    logging.info(f"{GREEN}Running assetfinder for {domain}...{GREEN}")
    try:
        subprocess.run(['assetfinder', '-subs-only', domain], stdout=open(f"{domain}/sources/assetfinder.txt", 'w'), check=True)
        subprocess.run(f"cat {domain}/sources/*.txt > {domain}/sources/all.txt", shell=True, check=True)
        logging.info(f"{GREEN}assetfinder completed for {domain}.{GREEN}")
    except subprocess.CalledProcessError:
        logging.error(f"{RED}Error: assetfinder failed for {domain}.{RED}")

# Function for HTTP probing
def run_http_probe(domain):
    logging.info(f"{GREEN}Probing HTTP for {domain}...{RED}")
    try:
        subprocess.run(f"cat {domain}/sources/all.txt | httprobe | tee {domain}/result/httpx/httpx.txt", shell=True, check=True)
        logging.info(f"{GREEN}HTTP probing completed for {domain}.{GREEN}")
    except subprocess.CalledProcessError:
        logging.error(f"{RED}Error: HTTP probing failed for {domain}.{RED}")

# Function for extracting Wayback URLs
def extract_wayback_urls(domain):
    logging.info(f"{YELLOW}Extracting Wayback URLs for {domain}...{RED}")
    try:
        subprocess.run(f"cat {domain}/result/httpx/httpx.txt | waybackurls | anew {domain}/result/wayback/wayback-tmp.txt", shell=True, check=True)
        subprocess.run(f"cat {domain}/result/wayback/wayback-tmp.txt | egrep -v '\\.woff|\\.ttf|\\.svg|\\.eot|\\.png|\\.jpeg|\\.jpg|\\.png|\\.css|\\.ico' | sed 's/:80//g;s/:443//g' | sort -u > {domain}/result/wayback/wayback.txt", shell=True, check=True)
        subprocess.run(f"rm {domain}/result/wayback/wayback-tmp.txt", shell=True, check=True)
        logging.info(f"{GREEN}Wayback URL extraction completed for {domain}.{GREEN}")
    except subprocess.CalledProcessError:
        logging.error(f"{RED}Error: Wayback URL extraction failed for {domain}.{RED}")

# Function for URL validation using ffuf
def validate_urls(domain):
    logging.info(f"{GREEN}Validating URLs with ffuf for {domain}...{GREEN}")
    try:
        subprocess.run(f"cat {domain}/result/wayback/wayback.txt | ffuf -c -u 'FUZZ' -w - -of csv -o {domain}/result/wayback/valid-tmp.txt -t 100 -rate 1000", shell=True, check=True)
        subprocess.run(f"cat {domain}/result/wayback/valid-tmp.txt | grep http | awk -F ',' '{{print $1}}' >> {domain}/result/wayback/valid.txt", shell=True, check=True)
        subprocess.run(f"rm {domain}/result/wayback/valid-tmp.txt", shell=True, check=True)
        logging.info(f"{GREEN}URL validation completed for {domain}.{GREEN}")
    except subprocess.CalledProcessError:
        logging.error(f"{RED}Error: URL validation failed for {domain}.{RED}")

# Function for finding JS files
def find_js_files(domain):
    logging.info(f"{GREEN}Searching for JS files in Wayback URLs for {domain}...{GREEN}")
    try:
        subprocess.run(f"cat {domain}/result/wayback/valid.txt | grep '.js$' | uniq | sort > {domain}/result/js/js.txt", shell=True, check=True)
        subprocess.run(f"cat {domain}/result/js/js.txt | while read url; do secretfinder.py -i $url -o cli >> {domain}/result/js/secret.txt; done", shell=True, check=True)
        logging.info(f"{GREEN}JS file search completed for {domain}.{GREEN}")
    except subprocess.CalledProcessError:
        logging.error(f"{RED}Error: JS file search failed for {domain}.{RED}")

# Function to send results to Telegram
def send_to_telegram(domain):
    try:
        config = read_config('config.json')
        token = config['telegram_token']
        chat_id = config['telegram_chat_id']

        message = f"Scan completed for domain: {domain}. Sending all results from {domain}/..."
        subprocess.run(f"curl -s -X POST 'https://api.telegram.org/bot{token}/sendMessage' -d chat_id={chat_id} -d text={message}", shell=True)

        for root, dirs, files in os.walk(domain):
            for file in files:
                subprocess.run(f"curl -s -F chat_id={chat_id} -F document=@{os.path.join(root, file)} 'https://api.telegram.org/bot{token}/sendDocument'", shell=True)

        final_message = f"All files from {domain}/ have been sent."
        subprocess.run(f"curl -s -X POST 'https://api.telegram.org/bot{token}/sendMessage' -d chat_id={chat_id} -d text={final_message}", shell=True)
        logging.info(f"{GREEN}All files sent to Telegram for {domain}.{GREEN}")
    except Exception as e:
        logging.error(f"{RED}Error: Failed to send results to Telegram for {domain}. {e}{RED}")

# Function to read config from JSON
def read_config(config_file):
    with open(config_file, 'r') as f:
        config = json.load(f)
    return config

# Function to process a single domain
def process_domain(domain):
    # Clear the terminal screen for better visibility
    os.system('cls' if os.name == 'nt' else 'clear')  # Clear terminal for Windows or Unix

    logging.info(f"{CYAN}Processing domain: {domain}{CYAN}")
    
    # Running various functions related to domain processing
    create_directories(domain)
    run_subfinder(domain)
    run_assetfinder(domain)
    run_http_probe(domain)
    extract_wayback_urls(domain)
    validate_urls(domain)
    find_js_files(domain)
    send_to_telegram(domain)
    
    # Clean up empty directories
    delete_empty_directories(domain)
    
    logging.info(f"{CYAN}Processing completed for {domain}.{CYAN}")

# Help function through argparse
def main():
    parser = argparse.ArgumentParser(
        description="Mass JS Finder - A tool for finding JS files and secrets in domains.",
        formatter_class=argparse.RawTextHelpFormatter
    )
    parser.add_argument('-t', '--target', type=str, help='Single target domain to scan')
    parser.add_argument('-l', '--list', type=str, help='File containing a list of domains to scan')

    # Parse arguments
    args = parser.parse_args()

    # Handle target input
    if args.target:
        domain = args.target
        if validate_input(domain):
            process_domain(domain)
    elif args.list:
        file_path = args.list
        if os.path.isfile(file_path):
            with open(file_path, 'r') as file:
                domains = [line.strip() for line in file.readlines() if line.strip() and line.strip() != '#']
            total_domains = len(domains)
            with concurrent.futures.ThreadPoolExecutor() as executor:
                futures = []
                with tqdm(total=total_domains) as pbar:
                    for i, domain in enumerate(domains, 1):
                        futures.append(executor.submit(process_domain, domain))
                        pbar.update(1)
                    concurrent.futures.wait(futures)
        else:
            logging.error(f"{RED}The provided file does not exist or is invalid.{RED}")
    else:
        logging.error(f"{RED}Please provide either a single domain (-t) or a list of domains (-l) or (-h) for help{RED}")

if __name__ == "__main__":
    main()
