import os
import subprocess
import time
import logging
import concurrent.futures
import pyfiglet
import json
import re
import argparse
import sys
import requests
import ipaddress
import shutil
from logging.handlers import RotatingFileHandler
from rich.console import Console
from rich.panel import Panel
from rich.progress import Progress, SpinnerColumn, BarColumn, TextColumn
from rich.table import Table
from rich.text import Text

# Initialize Rich Console for better terminal output
console = Console()

def print_banner():
    """Prints a visually appealing banner using pyfiglet and Rich."""
    banner_text = pyfiglet.figlet_format("JSFvck", font="block")
    info_text = (
        "Copyright (c) [2025] [Anonre]\n"
        "All rights reserved.\n\n"
        "Unauthorized copying, distribution, or modification is prohibited.\n"
        "Author: Anonre | Feel free to contribute!"
    )

    panel = Panel(
        Text(banner_text, justify="center") + "\n" + Text(info_text, justify="center"),
        title="[bold green]JSFvck[/bold green]",
        border_style="green",
        padding=(1, 2)
    )
    console.print(panel)

# Setup enhanced logging
def setup_logging():
    """Sets up logging with rotation and Rich handler for console output."""
    os.makedirs("logs", exist_ok=True)
    log_format = '%(asctime)s - %(levelname)s - %(message)s'

    timestamp = time.strftime("%Y%m%d-%H%M%S")
    log_file = f'logs/scan_{timestamp}.log'

    # File handler for detailed logs
    handler = RotatingFileHandler(log_file, maxBytes=10**6, backupCount=10)
    handler.setFormatter(logging.Formatter(log_format))

    # Configure root logger
    logging.basicConfig(level=logging.INFO, format=log_format, handlers=[handler])

    return logging.getLogger()

# Stronger input validation
def validate_input(input_data):
    """Validates if input is a file, domain, IP address, or CIDR."""
    if os.path.isfile(input_data):
        return True

    domain_pattern = r'^(?:[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$'
    if re.match(domain_pattern, input_data):
        return True

    try:
        ipaddress.ip_address(input_data)
        return True
    except ValueError:
        pass

    try:
        ipaddress.ip_network(input_data, strict=False)
        return True
    except ValueError:
        pass

    console.print(f"[bold red]Error: Invalid input. Please provide a valid domain, IP, CIDR, or file path.[/bold red]")
    return False

# More structured directory creation
def create_directories(target):
    """Creates a structured set of directories for storing scan results."""
    directories = [
        "sources", "result", "result/wayback",
        "result/httpx", "result/js", "result/endpoints", "result/dns"
    ]
    created_count = 0
    for dir_name in directories:
        dir_path = f"{target}/{dir_name}"
        if not os.path.exists(dir_path):
            os.makedirs(dir_path)
            created_count += 1

    if created_count > 0:
        console.print(f"[green]Created {created_count} directories for [bold]{target}[/bold].[/green]")

# Function to delete empty directories
def delete_empty_directories(target):
    """Removes empty directories after a scan is complete."""
    removed = 0
    for root, dirs, files in os.walk(target, topdown=False):
        for dir_name in dirs:
            dir_path = os.path.join(root, dir_name)
            try:
                if not os.listdir(dir_path):
                    os.rmdir(dir_path)
                    removed += 1
            except OSError as e:
                logging.error(f"Failed to remove {dir_path}: {e}")

    if removed > 0:
        logging.info(f"Successfully removed {removed} empty directories from {target}.")


# Command execution helper
def run_command(command, output_file=None, shell=True, check=True):
    """Executes a shell command with improved error handling and optional output to file."""
    try:
        if output_file:
            with open(output_file, 'w', encoding='utf-8', errors='ignore') as f:
                subprocess.run(command, shell=shell, check=check, stdout=f, stderr=subprocess.PIPE, text=True)
        else:
            result = subprocess.run(command, shell=shell, check=check, capture_output=True, text=True, encoding='utf-8', errors='ignore')
            return result.stdout
    except subprocess.CalledProcessError as e:
        logging.error(f"Command execution failed: {command}\nError: {e.stderr}")
        return None
    except Exception as e:
        logging.error(f"An unexpected error occurred: {e}")
        return None

# Dependency check
def check_dependencies():
    """Checks for required external tools."""
    required_tools = ["subfinder", "assetfinder", "httprobe", "waybackurls", "ffuf", "gau", "dnsx", "httpx", "hakrawler"]
    missing_tools = [tool for tool in required_tools if not shutil.which(tool)]

    if missing_tools:
        console.print(f"[bold yellow]Warning: Missing tools: {', '.join(missing_tools)}[/bold yellow]")
        console.print("[cyan]Please install missing tools for full functionality.[/cyan]")
        return False

    console.print("[bold green]All required dependencies are installed.[/bold green]")
    return True

# --- Core Scanning Functions with Rich Progress ---

def run_subfinder(target, progress, task):
    """Runs subfinder to discover subdomains."""
    progress.update(task, description="[cyan]Running subfinder...")
    output_file = f"{target}/sources/subfinder.txt"
    command = f"subfinder -d {target} -all -silent -o {output_file}"
    run_command(command)
    progress.update(task, completed=1)

    if os.path.exists(output_file) and os.path.getsize(output_file) > 0:
        count = len(open(output_file).readlines())
        logging.info(f"Subfinder found {count} subdomains for {target}.")
    else:
        logging.warning(f"Subfinder found no subdomains for {target}.")

def run_assetfinder(target, progress, task):
    """Runs assetfinder and merges results."""
    progress.update(task, description="[cyan]Running assetfinder...")
    output_file = f"{target}/sources/assetfinder.txt"
    command = f"assetfinder --subs-only {target}"
    result = run_command(command)
    progress.update(task, completed=1)

    if result:
        with open(output_file, 'w') as f:
            f.write(result)
        count = len(result.strip().split('\n'))
        logging.info(f"Assetfinder found {count} subdomains for {target}.")
    else:
        logging.warning(f"Assetfinder found no subdomains for {target}.")

    # Merge all sources
    all_sources_file = f"{target}/sources/all.txt"
    run_command(f"cat {target}/sources/*.txt | sort -u > {all_sources_file}")

def run_dnsx(target, progress, task):
    """Runs DNSX for DNS resolution."""
    progress.update(task, description="[cyan]Resolving DNS...")
    input_file = f"{target}/sources/all.txt"
    output_file = f"{target}/result/dns/resolved.txt"

    if not os.path.exists(input_file) or os.path.getsize(input_file) == 0:
        logging.warning("No subdomains to resolve with DNSX.")
        progress.update(task, completed=1)
        return

    command = f"cat {input_file} | dnsx -silent -a -resp -o {output_file}"
    run_command(command)
    progress.update(task, completed=1)

    if os.path.exists(output_file) and os.path.getsize(output_file) > 0:
        count = len(open(output_file).readlines())
        logging.info(f"DNSX resolved {count} subdomains for {target}.")
    else:
        logging.warning("DNSX did not resolve any subdomains.")

def run_http_probe(target, progress, task):
    """Performs HTTP probing on discovered subdomains."""
    progress.update(task, description="[cyan]Probing for HTTP servers...")
    input_file = f"{target}/sources/all.txt"
    output_file = f"{target}/result/httpx/httpx.txt"

    if not os.path.exists(input_file) or os.path.getsize(input_file) == 0:
        logging.warning("No subdomains to probe.")
        progress.update(task, completed=1)
        return

    command = f"cat {input_file} | httprobe | tee {output_file}"
    run_command(command)
    progress.update(task, completed=1)

    if os.path.exists(output_file) and os.path.getsize(output_file) > 0:
        count = len(open(output_file).readlines())
        logging.info(f"HTTP probing found {count} active hosts for {target}.")
    else:
        logging.warning("No active HTTP hosts found.")

def extract_wayback_urls(target, progress, task):
    """Extracts URLs from Wayback Machine using multiple tools."""
    progress.update(task, description="[cyan]Extracting Wayback URLs...")
    input_file = f"{target}/result/httpx/httpx.txt"
    output_tmp = f"{target}/result/wayback/wayback-tmp.txt"
    output_file = f"{target}/result/wayback/wayback.txt"

    if not os.path.exists(input_file) or os.path.getsize(input_file) == 0:
        logging.warning("No active hosts to extract from Wayback.")
        progress.update(task, completed=1)
        return

    run_command(f"cat {input_file} | waybackurls > {output_tmp}")
    run_command(f"cat {input_file} | gau --threads 5 >> {output_tmp}")

    filter_cmd = f"cat {output_tmp} | grep -ivE '\\.(woff|ttf|svg|eot|png|jpeg|jpg|css|ico)$' | sed 's/:80//g;s/:443//g' | sort -u > {output_file}"
    run_command(filter_cmd)

    if os.path.exists(output_tmp):
        os.remove(output_tmp)

    progress.update(task, completed=1)

    if os.path.exists(output_file) and os.path.getsize(output_file) > 0:
        count = len(open(output_file).readlines())
        logging.info(f"Found {count} Wayback URLs for {target}.")
    else:
        logging.warning("No Wayback URLs found.")

def validate_urls(target, progress, task):
    """Validates extracted URLs using ffuf."""
    progress.update(task, description="[cyan]Validating URLs...")
    input_file = f"{target}/result/wayback/wayback.txt"
    output_tmp = f"{target}/result/wayback/valid-tmp.txt"
    output_file = f"{target}/result/wayback/valid.txt"

    if not os.path.exists(input_file) or os.path.getsize(input_file) == 0:
        logging.warning("No URLs to validate.")
        progress.update(task, completed=1)
        return

    command = f"cat {input_file} | ffuf -c -u 'FUZZ' -w - -of csv -o {output_tmp} -t 50 -rate 750"
    run_command(command)

    if os.path.exists(output_tmp) and os.path.getsize(output_tmp) > 0:
        run_command(f"cat {output_tmp} | grep http | awk -F ',' '{{print $1}}' > {output_file}")
        if os.path.exists(output_tmp):
            os.remove(output_tmp)

        if os.path.exists(output_file) and os.path.getsize(output_file) > 0:
            count = len(open(output_file).readlines())
            logging.info(f"URL validation found {count} valid URLs for {target}.")
        else:
            logging.warning("No valid URLs found.")
    else:
        logging.warning("No results from ffuf validation.")

    progress.update(task, completed=1)

def find_js_files(target, progress, task):
    """Finds JS files, secrets, and API endpoints."""
    progress.update(task, description="[cyan]Finding JS files & secrets...")
    input_file = f"{target}/result/wayback/valid.txt"
    output_file = f"{target}/result/js/js.txt"
    secret_file = f"{target}/result/js/secret.txt"
    endpoints_file = f"{target}/result/endpoints/api_endpoints.txt"

    if not os.path.exists(input_file) or os.path.getsize(input_file) == 0:
        logging.warning("No valid URLs to search for JS files.")
        progress.update(task, completed=1)
        return

    run_command(f"cat {input_file} | grep -E '\\.js($|\\?)' | sort -u > {output_file}")

    if os.path.exists(output_file) and os.path.getsize(output_file) > 0:
        js_count = len(open(output_file).readlines())
        logging.info(f"Found {js_count} JS files for {target}.")

        run_command(f"cat {output_file} | xargs -I% bash -c 'secretfinder -i % -o cli' > {secret_file}")
        run_command(f"cat {output_file} | hakrawler -js -depth 2 -scope subs -plain | grep -E '^(https?://)' | sort -u > {endpoints_file}")

        if os.path.exists(endpoints_file) and os.path.getsize(endpoints_file) > 0:
            endpoint_count = len(open(endpoints_file).readlines())
            logging.info(f"API endpoint extraction found {endpoint_count} endpoints.")
    else:
        logging.warning("No JS files found.")

    progress.update(task, completed=1)

def read_config(config_file):
    """Reads configuration from a JSON file with defaults."""
    default_config = {
        "discord_webhook_url": "",
        "telegram_bot_token": "",
        "telegram_chat_id": "",
        "threads": 5,
        "rate_limit": 750
    }
    if not os.path.exists(config_file):
        logging.warning(f"Config file {config_file} not found. Using defaults.")
        return default_config
    try:
        with open(config_file, 'r') as f:
            config = json.load(f)
        for key in default_config:
            if key not in config:
                config[key] = default_config[key]
        return config
    except Exception as e:
        logging.error(f"Error reading config: {e}. Using defaults.")
        return default_config

def create_summary_string(target):
    """Creates a string summary of the scan results."""
    summary = [f"Scan Summary for: {target}"]
    summary_files = {
        "Subdomains": f"{target}/sources/all.txt",
        "Active HTTP Hosts": f"{target}/result/httpx/httpx.txt",
        "JS Files": f"{target}/result/js/js.txt",
        "API Endpoints": f"{target}/result/endpoints/api_endpoints.txt",
        "Secrets Found in JS": f"{target}/result/js/secret.txt"
    }
    for name, path in summary_files.items():
        count = 0
        if os.path.exists(path) and os.path.getsize(path) > 0:
            count = len(open(path).readlines())
        summary.append(f"{name}: {count}")
    
    summary.append(f"Scan Time: {time.strftime('%Y-%m-%d %H:%M:%S')}")
    return "\n".join(summary)


def send_to_discord(target):
    """Sends scan summary and important files to a Discord webhook."""
    try:
        config = read_config('config.json')
        webhook_url = config.get('discord_webhook_url')

        if not webhook_url:
            logging.error("Discord webhook URL not found in config.json.")
            return

        summary = create_summary_string(target)
        message = {
            "embeds": [{
                "title": f"Scan Report for {target}",
                "description": f"```\n{summary}\n```",
                "color": 3447003
            }]
        }
        response = requests.post(webhook_url, json=message)
        if response.status_code not in [200, 204]:
            logging.error(f"Failed to send message to Discord. Status: {response.status_code}")
            return

        important_files = [
            f"{target}/result/js/secret.txt",
            f"{target}/result/endpoints/api_endpoints.txt",
            f"{target}/result/httpx/httpx.txt"
        ]
        for file_path in important_files:
            if os.path.exists(file_path) and os.path.getsize(file_path) > 0:
                with open(file_path, 'rb') as f:
                    files = {'file': (os.path.basename(file_path), f)}
                    requests.post(webhook_url, files=files)
        
        console.print("[bold green]Important results sent to Discord.[/bold green]")
    except Exception as e:
        logging.error(f"Failed to send results to Discord: {e}")

# --- Main Processing and Orchestration ---

def process_domain(target):
    """Orchestrates the entire scanning process for a single target."""
    start_time = time.time()
    console.print(Panel(f"Starting scan for: [bold cyan]{target}[/bold cyan]", title="[bold green]Scan Initialized[/bold green]", border_style="green"))

    create_directories(target)

    scan_steps = [
        ("Subdomain Enumeration (Subfinder)", run_subfinder),
        ("Asset Discovery (Assetfinder)", run_assetfinder),
        ("DNS Resolution (DNSX)", run_dnsx),
        ("HTTP Probing (HTTProbe)", run_http_probe),
        ("Wayback URL Extraction", extract_wayback_urls),
        ("URL Validation (FFUF)", validate_urls),
        ("JS Analysis (Hakrawler/SecretFinder)", find_js_files)
    ]

    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        BarColumn(),
        transient=True
    ) as progress:
        for name, func in scan_steps:
            task = progress.add_task(name, total=1)
            func(target, progress, task)

    delete_empty_directories(target)
    execution_time = time.time() - start_time

    console.print(f"\n[bold green]Scan for [cyan]{target}[/cyan] completed in {execution_time:.2f} seconds.[/bold green]")
    create_summary_table(target)
    send_to_discord(target)

def create_summary_table(target):
    """Creates and prints a summary of the scan results in a table."""
    table = Table(title=f"Scan Summary for {target}", show_header=True, header_style="bold magenta")
    table.add_column("Category", style="cyan", no_wrap=True)
    table.add_column("Count", style="green", justify="right")

    summary_files = {
        "Subdomains": f"{target}/sources/all.txt",
        "Active HTTP Hosts": f"{target}/result/httpx/httpx.txt",
        "JS Files": f"{target}/result/js/js.txt",
        "API Endpoints": f"{target}/result/endpoints/api_endpoints.txt",
        "Secrets Found in JS": f"{target}/result/js/secret.txt"
    }

    for name, path in summary_files.items():
        count = 0
        if os.path.exists(path) and os.path.getsize(path) > 0:
            count = len(open(path).readlines())
        table.add_row(name, str(count))

    console.print(table)


# --- Main Execution ---

def main():
    """Main function to parse arguments and initiate scans."""
    setup_logging()
    print_banner()

    parser = argparse.ArgumentParser(
        description="JSFvck - A powerful tool for discovering JS files, API endpoints, and secrets.",
        formatter_class=argparse.RawTextHelpFormatter
    )
    parser.add_argument('-t', '--target', type=str, help='Single target domain/IP/CIDR to scan')
    parser.add_argument('-l', '--list', type=str, help='File containing a list of targets to scan')
    parser.add_argument('--threads', type=int, default=5, help='Number of threads for parallel scanning (default: 5)')
    parser.add_argument('--config', type=str, default='config.json', help='Path to config file (default: config.json)')
    parser.add_argument('--output-dir', type=str, help='Directory to save results (default: current directory)')

    args = parser.parse_args()

    if args.output_dir:
        os.makedirs(args.output_dir, exist_ok=True)
        os.chdir(args.output_dir)

    if not check_dependencies():
        sys.exit(1)

    if args.target:
        if validate_input(args.target):
            process_domain(args.target)
    elif args.list:
        if os.path.isfile(args.list):
            with open(args.list, 'r') as f:
                targets = [line.strip() for line in f if line.strip() and not line.strip().startswith('#')]

            console.print(f"[bold blue]Processing {len(targets)} targets from {args.list} with {args.threads} threads.[/bold blue]")
            with concurrent.futures.ThreadPoolExecutor(max_workers=args.threads) as executor:
                list(executor.map(process_domain, targets))
            console.print("[bold green]All scans completed![/bold green]")
        else:
            console.print(f"[bold red]Error: The file '{args.list}' does not exist.[/bold red]")
    else:
        parser.print_help()


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        console.print("\n[bold yellow]Program interrupted by user. Shutting down.[/bold yellow]")
    except Exception as e:
        console.print(f"[bold red]An unexpected error occurred: {e}[/bold red]")
        logging.error("An unexpected error occurred", exc_info=True)
