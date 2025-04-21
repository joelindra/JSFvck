import os
import subprocess
import time
import logging
import concurrent.futures
import pyfiglet
import json
import re
import argparse
import platform
import requests
import ipaddress
import sys
from tqdm import tqdm
from logging.handlers import RotatingFileHandler
import shutil

def print_banner():
    banner = """
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
"""
    print(banner)
    
class Colors:
    MAGENTA = '\033[0;35m'
    CYAN = '\033[0;36m'
    GREEN = '\033[0;32m'
    RED = '\033[0;31m'
    YELLOW = '\033[1;33m'
    BLUE = '\033[0;34m'
    WHITE = '\033[1;37m'
    RESET = '\033[0m'

def setup_logging():
    os.makedirs("logs", exist_ok=True)
    log_format = '%(asctime)s - %(levelname)s - %(message)s'
    logging.basicConfig(level=logging.INFO, format=log_format)
    timestamp = time.strftime("%Y%m%d-%H%M%S")
    log_file = f'logs/scan_{timestamp}.log'
    handler = RotatingFileHandler(log_file, maxBytes=10**6, backupCount=10)
    handler.setFormatter(logging.Formatter(log_format))
    logger = logging.getLogger()
    logger.addHandler(handler)
    return logger

def ascii_art(text):
    try:
        return pyfiglet.figlet_format(text, font="block")
    except Exception as e:
        logging.warning(f"Couldn't generate ASCII art: {e}")
        return text

def validate_input(input_data):
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
    
    logging.error(f"{Colors.RED}Input tidak valid. Harap masukkan domain, IP, CIDR, atau path file yang valid.{Colors.RESET}")
    return False

def create_directories(target):
    directories = [
        "sources", 
        "result",
        "result/nuclei", 
        "result/wayback",
        "result/httpx", 
        "result/exploit", 
        "result/js",
        "result/screenshots",
        "result/vulnerabilities",
        "result/endpoints",
        "result/dns",
        "result/ports"
    ]
    
    created = 0
    for dir_name in directories:
        dir_path = f"{target}/{dir_name}"
        if not os.path.exists(dir_path):
            os.makedirs(dir_path, exist_ok=True)
            created += 1
    
    logging.info(f"{Colors.GREEN}Dibuat {created} direktori untuk {target}{Colors.RESET}")

def delete_empty_directories(target):
    removed = 0
    for root, dirs, files in os.walk(target, topdown=False):
        for dir_name in dirs:
            dir_path = os.path.join(root, dir_name)
            try:
                if not os.listdir(dir_path):
                    os.rmdir(dir_path)
                    removed += 1
            except OSError as e:
                logging.error(f"{Colors.RED}Gagal menghapus {dir_path}: {e}{Colors.RESET}")
    
    if removed > 0:
        logging.info(f"{Colors.GREEN}Berhasil menghapus {removed} direktori kosong dari {target}{Colors.RESET}")

def run_command(command, output_file=None, shell=True, check=True):
    try:
        if output_file:
            with open(output_file, 'w') as f:
                subprocess.run(command, shell=shell, check=check, stdout=f, stderr=subprocess.PIPE)
        else:
            result = subprocess.run(command, shell=shell, check=check, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            return result.stdout.decode('utf-8', errors='ignore')
    except subprocess.CalledProcessError as e:
        logging.error(f"{Colors.RED}Kesalahan menjalankan perintah: {command}\nError: {e}{Colors.RESET}")
        logging.error(f"STDERR: {e.stderr.decode('utf-8', errors='ignore')}")
        return None
    except Exception as e:
        logging.error(f"{Colors.RED}Kesalahan tak terduga: {e}{Colors.RESET}")
        return None

def check_dependencies():
    required_tools = [
        "subfinder", "assetfinder", "httprobe", "waybackurls", "ffuf", 
        "nuclei", "nmap", "gowitness", "hakrawler", "gau", "dnsx", "httpx"
    ]
    
    missing_tools = []
    
    for tool in required_tools:
        try:
            subprocess.run(["which", tool], check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        except subprocess.CalledProcessError:
            missing_tools.append(tool)
    
    if missing_tools:
        logging.warning(f"{Colors.YELLOW}Tool yang tidak ditemukan: {', '.join(missing_tools)}{Colors.RESET}")
        logging.info(f"{Colors.CYAN}Silakan install tool yang hilang untuk fungsionalitas penuh.{Colors.RESET}")
        return False
    
    logging.info(f"{Colors.GREEN}Semua dependensi yang dibutuhkan sudah tersedia.{Colors.RESET}")
    return True

def run_subfinder(target):
    logging.info(f"{Colors.GREEN}Menjalankan subfinder untuk {target}...{Colors.RESET}")
    output_file = f"{target}/sources/subfinder.txt"
    
    try:
        command = f"subfinder -d {target} -all -o {output_file}"
        run_command(command)
        
        if os.path.exists(output_file) and os.path.getsize(output_file) > 0:
            count = len(open(output_file).readlines())
            logging.info(f"{Colors.GREEN}subfinder selesai untuk {target}. Ditemukan {count} subdomain.{Colors.RESET}")
        else:
            logging.warning(f"{Colors.YELLOW}subfinder tidak menemukan subdomain untuk {target}.{Colors.RESET}")
    except Exception as e:
        logging.error(f"{Colors.RED}Error: subfinder gagal untuk {target}. {e}{Colors.RESET}")

def run_assetfinder(target):
    logging.info(f"{Colors.GREEN}Menjalankan assetfinder untuk {target}...{Colors.RESET}")
    output_file = f"{target}/sources/assetfinder.txt"
    
    try:
        command = f"assetfinder -subs-only {target} > {output_file}"
        run_command(command)
        
        run_command(f"cat {target}/sources/*.txt | sort -u > {target}/sources/all.txt")
        
        if os.path.exists(output_file) and os.path.getsize(output_file) > 0:
            count = len(open(output_file).readlines())
            logging.info(f"{Colors.GREEN}assetfinder selesai untuk {target}. Ditemukan {count} subdomain.{Colors.RESET}")
        else:
            logging.warning(f"{Colors.YELLOW}assetfinder tidak menemukan subdomain untuk {target}.{Colors.RESET}")
    except Exception as e:
        logging.error(f"{Colors.RED}Error: assetfinder gagal untuk {target}. {e}{Colors.RESET}")

def run_dnsx(target):
    logging.info(f"{Colors.BLUE}Menjalankan DNSX untuk {target}...{Colors.RESET}")
    input_file = f"{target}/sources/all.txt"
    output_file = f"{target}/result/dns/resolved.txt"
    
    if not os.path.exists(input_file) or os.path.getsize(input_file) == 0:
        logging.warning(f"{Colors.YELLOW}Tidak ada subdomain untuk diresolve dengan DNSX.{Colors.RESET}")
        return
    
    try:
        command = f"cat {input_file} | dnsx -silent -a -resp -o {output_file}"
        run_command(command)
        
        if os.path.exists(output_file) and os.path.getsize(output_file) > 0:
            count = len(open(output_file).readlines())
            logging.info(f"{Colors.GREEN}DNSX selesai untuk {target}. Berhasil meresolve {count} subdomain.{Colors.RESET}")
        else:
            logging.warning(f"{Colors.YELLOW}DNSX tidak berhasil meresolve subdomain.{Colors.RESET}")
    except Exception as e:
        logging.error(f"{Colors.RED}Error: DNSX gagal untuk {target}. {e}{Colors.RESET}")

def run_http_probe(target):
    logging.info(f"{Colors.GREEN}Melakukan probing HTTP untuk {target}...{Colors.RESET}")
    input_file = f"{target}/sources/all.txt"
    output_file = f"{target}/result/httpx/httpx.txt"
    
    if not os.path.exists(input_file) or os.path.getsize(input_file) == 0:
        logging.warning(f"{Colors.YELLOW}Tidak ada subdomain untuk di-probe.{Colors.RESET}")
        return
    
    try:
        command = f"cat {input_file} | httprobe | tee {output_file}"
        run_command(command)
        
        if os.path.exists(output_file) and os.path.getsize(output_file) > 0:
            count = len(open(output_file).readlines())
            logging.info(f"{Colors.GREEN}HTTP probing selesai untuk {target}. Ditemukan {count} host aktif.{Colors.RESET}")
        else:
            logging.warning(f"{Colors.YELLOW}Tidak menemukan host HTTP aktif.{Colors.RESET}")
    except Exception as e:
        logging.error(f"{Colors.RED}Error: HTTP probing gagal untuk {target}. {e}{Colors.RESET}")

def run_screenshots(target):
    logging.info(f"{Colors.BLUE}Mengambil screenshot untuk {target}...{Colors.RESET}")
    input_file = f"{target}/result/httpx/httpx.txt"
    output_dir = f"{target}/result/screenshots"
    
    if not os.path.exists(input_file) or os.path.getsize(input_file) == 0:
        logging.warning(f"{Colors.YELLOW}Tidak ada host untuk diambil screenshot.{Colors.RESET}")
        return
    
    try:
        command = f"gowitness file -f {input_file} --screenshot-path {output_dir} -P {output_dir}/gowitness.sqlite3"
        run_command(command)
        
        screenshots = [f for f in os.listdir(output_dir) if f.endswith('.png')]
        if screenshots:
            logging.info(f"{Colors.GREEN}Screenshot selesai untuk {target}. Diambil {len(screenshots)} screenshot.{Colors.RESET}")
        else:
            logging.warning(f"{Colors.YELLOW}Tidak berhasil mengambil screenshot.{Colors.RESET}")
    except Exception as e:
        logging.error(f"{Colors.RED}Error: Screenshot gagal untuk {target}. {e}{Colors.RESET}")

def run_port_scan(target):
    logging.info(f"{Colors.BLUE}Melakukan port scanning untuk {target}...{Colors.RESET}")
    input_file = f"{target}/result/dns/resolved.txt"
    output_file = f"{target}/result/ports/nmap_results.txt"
    
    if not os.path.exists(input_file) or os.path.getsize(input_file) == 0:
        logging.warning(f"{Colors.YELLOW}Tidak ada host untuk di-scan.{Colors.RESET}")
        return
    
    try:
        ips_file = f"{target}/result/dns/ips.txt"
        run_command(f"grep -oE '([0-9]{{1,3}}\\.){{3}}[0-9]{{1,3}}' {input_file} | sort -u > {ips_file}")
        
        if os.path.exists(ips_file) and os.path.getsize(ips_file) > 0:
            command = f"nmap -iL {ips_file} -T4 -p- --open -oN {output_file}"
            run_command(command)
            
            if os.path.exists(output_file) and os.path.getsize(output_file) > 0:
                logging.info(f"{Colors.GREEN}Port scanning selesai untuk {target}.{Colors.RESET}")
            else:
                logging.warning(f"{Colors.YELLOW}Tidak menemukan port terbuka.{Colors.RESET}")
        else:
            logging.warning(f"{Colors.YELLOW}Tidak ada IP untuk di-scan.{Colors.RESET}")
    except Exception as e:
        logging.error(f"{Colors.RED}Error: Port scanning gagal untuk {target}. {e}{Colors.RESET}")

def extract_wayback_urls(target):
    logging.info(f"{Colors.YELLOW}Mengekstrak Wayback URLs untuk {target}...{Colors.RESET}")
    input_file = f"{target}/result/httpx/httpx.txt"
    output_tmp = f"{target}/result/wayback/wayback-tmp.txt"
    output_file = f"{target}/result/wayback/wayback.txt"
    
    if not os.path.exists(input_file) or os.path.getsize(input_file) == 0:
        logging.warning(f"{Colors.YELLOW}Tidak ada host untuk diekstrak dari Wayback.{Colors.RESET}")
        return
    
    try:
        run_command(f"cat {input_file} | waybackurls > {output_tmp}")
        run_command(f"cat {input_file} | gau --threads 5 >> {output_tmp}")
        
        run_command(f"cat {output_tmp} | egrep -v '\\.woff|\\.ttf|\\.svg|\\.eot|\\.png|\\.jpeg|\\.jpg|\\.png|\\.css|\\.ico' | sed 's/:80//g;s/:443//g' | sort -u > {output_file}")
        
        if os.path.exists(output_tmp):
            os.remove(output_tmp)
        
        if os.path.exists(output_file) and os.path.getsize(output_file) > 0:
            count = len(open(output_file).readlines())
            logging.info(f"{Colors.GREEN}Wayback URL extraction selesai untuk {target}. Ditemukan {count} URL.{Colors.RESET}")
        else:
            logging.warning(f"{Colors.YELLOW}Tidak menemukan URL dari Wayback.{Colors.RESET}")
    except Exception as e:
        logging.error(f"{Colors.RED}Error: Wayback URL extraction gagal untuk {target}. {e}{Colors.RESET}")

def validate_urls(target):
    logging.info(f"{Colors.GREEN}Memvalidasi URLs dengan ffuf untuk {target}...{Colors.RESET}")
    input_file = f"{target}/result/wayback/wayback.txt"
    output_tmp = f"{target}/result/wayback/valid-tmp.txt"
    output_file = f"{target}/result/wayback/valid.txt"
    
    if not os.path.exists(input_file) or os.path.getsize(input_file) == 0:
        logging.warning(f"{Colors.YELLOW}Tidak ada URL untuk divalidasi.{Colors.RESET}")
        return
    
    try:
        command = f"cat {input_file} | ffuf -c -u 'FUZZ' -w - -of csv -o {output_tmp} -t 50 -rate 750"
        run_command(command)
        
        if os.path.exists(output_tmp) and os.path.getsize(output_tmp) > 0:
            run_command(f"cat {output_tmp} | grep http | awk -F ',' '{{print $1}}' > {output_file}")
            if os.path.exists(output_tmp):
                os.remove(output_tmp)
                
            if os.path.exists(output_file) and os.path.getsize(output_file) > 0:
                count = len(open(output_file).readlines())
                logging.info(f"{Colors.GREEN}URL validation selesai untuk {target}. {count} URL valid.{Colors.RESET}")
            else:
                logging.warning(f"{Colors.YELLOW}Tidak menemukan URL valid.{Colors.RESET}")
        else:
            logging.warning(f"{Colors.YELLOW}Tidak ada hasil dari ffuf.{Colors.RESET}")
    except Exception as e:
        logging.error(f"{Colors.RED}Error: URL validation gagal untuk {target}. {e}{Colors.RESET}")

def find_js_files(target):
    logging.info(f"{Colors.GREEN}Mencari file JS di Wayback URLs untuk {target}...{Colors.RESET}")
    input_file = f"{target}/result/wayback/valid.txt"
    output_file = f"{target}/result/js/js.txt"
    secret_file = f"{target}/result/js/secret.txt"
    endpoints_file = f"{target}/result/endpoints/api_endpoints.txt"
    
    if not os.path.exists(input_file) or os.path.getsize(input_file) == 0:
        logging.warning(f"{Colors.YELLOW}Tidak ada URL untuk dicari file JS-nya.{Colors.RESET}")
        return
    
    try:
        run_command(f"cat {input_file} | grep -E '\\.js($|\\?)' | sort -u > {output_file}")
        
        if os.path.exists(output_file) and os.path.getsize(output_file) > 0:
            js_count = len(open(output_file).readlines())
            logging.info(f"{Colors.GREEN}Ditemukan {js_count} file JS untuk {target}.{Colors.RESET}")
            
            run_command(f"cat {output_file} | xargs -I% bash -c 'echo \"Analyzing %...\"; secretfinder -i % -o cli' > {secret_file}")
            
            run_command(f"cat {output_file} | hakrawler -js -depth 2 -scope subs -plain | grep -E '^(https?://)' | sort -u > {endpoints_file}")
            
            endpoint_count = 0
            if os.path.exists(endpoints_file) and os.path.getsize(endpoints_file) > 0:
                endpoint_count = len(open(endpoints_file).readlines())
            
            logging.info(f"{Colors.GREEN}Ekstraksi API endpoints selesai. Ditemukan {endpoint_count} endpoints.{Colors.RESET}")
        else:
            logging.warning(f"{Colors.YELLOW}Tidak menemukan file JS.{Colors.RESET}")
    except Exception as e:
        logging.error(f"{Colors.RED}Error: Pencarian file JS gagal untuk {target}. {e}{Colors.RESET}")

def run_nuclei(target):
    logging.info(f"{Colors.BLUE}Menjalankan Nuclei untuk {target}...{Colors.RESET}")
    input_file = f"{target}/result/httpx/httpx.txt"
    output_file = f"{target}/result/nuclei/vulnerabilities.txt"
    json_output = f"{target}/result/nuclei/vulnerabilities.json"
    
    if not os.path.exists(input_file) or os.path.getsize(input_file) == 0:
        logging.warning(f"{Colors.YELLOW}Tidak ada host untuk di-scan dengan Nuclei.{Colors.RESET}")
        return
    
    try:
        command = f"nuclei -l {input_file} -severity low,medium,high,critical -o {output_file} -json -json-export {json_output}"
        run_command(command)
        
        if os.path.exists(output_file) and os.path.getsize(output_file) > 0:
            vuln_count = len(open(output_file).readlines())
            logging.info(f"{Colors.GREEN}Nuclei selesai untuk {target}. Ditemukan {vuln_count} vulnerabilities.{Colors.RESET}")
        else:
            logging.warning(f"{Colors.YELLOW}Tidak menemukan vulnerabilities dengan Nuclei.{Colors.RESET}")
    except Exception as e:
        logging.error(f"{Colors.RED}Error: Nuclei gagal untuk {target}. {e}{Colors.RESET}")

def send_to_discord(target):
    try:
        config = read_config('config.json')
        webhook_url = config.get('discord_webhook_url')
        
        if not webhook_url:
            logging.error(f"{Colors.RED}URL webhook Discord tidak ditemukan di config.json.{Colors.RESET}")
            return
        
        summary = create_summary(target)
        
        message = {
            "content": f"Scan selesai untuk domain: {target}",
            "embeds": [
                {
                    "title": f"Ringkasan Hasil Scan {target}",
                    "description": summary,
                    "color": 3447003
                }
            ]
        }
        
        response = requests.post(
            webhook_url,
            json=message
        )
        
        if response.status_code != 204:
            logging.error(f"{Colors.RED}Gagal mengirim pesan ke Discord. Status: {response.status_code}{Colors.RESET}")
            return
        
        important_files = [
            f"{target}/result/nuclei/vulnerabilities.txt",
            f"{target}/result/js/secret.txt",
            f"{target}/result/endpoints/api_endpoints.txt",
            f"{target}/result/httpx/httpx.txt"
        ]
        
        for file_path in important_files:
            if os.path.exists(file_path) and os.path.getsize(file_path) > 0:
                with open(file_path, 'rb') as f:
                    files = {'file': (os.path.basename(file_path), f)}
                    response = requests.post(webhook_url, files=files)
                    
                    if response.status_code != 204:
                        logging.error(f"{Colors.RED}Gagal mengirim file {file_path} ke Discord.{Colors.RESET}")
        
        logging.info(f"{Colors.GREEN}Hasil penting berhasil dikirim ke Discord untuk {target}.{Colors.RESET}")
    except Exception as e:
        logging.error(f"{Colors.RED}Error: Gagal mengirim hasil ke Discord untuk {target}. {e}{Colors.RESET}")

def create_summary(target):
    summary = []
    
    subdomain_file = f"{target}/sources/all.txt"
    if os.path.exists(subdomain_file) and os.path.getsize(subdomain_file) > 0:
        count = len(open(subdomain_file).readlines())
        summary.append(f"Subdomain: {count}")
    
    httpx_file = f"{target}/result/httpx/httpx.txt"
    if os.path.exists(httpx_file) and os.path.getsize(httpx_file) > 0:
        count = len(open(httpx_file).readlines())
        summary.append(f"Host HTTP aktif: {count}")
    
    js_file = f"{target}/result/js/js.txt"
    if os.path.exists(js_file) and os.path.getsize(js_file) > 0:
        count = len(open(js_file).readlines())
        summary.append(f"File JS: {count}")
    
    vuln_file = f"{target}/result/nuclei/vulnerabilities.txt"
    if os.path.exists(vuln_file) and os.path.getsize(vuln_file) > 0:
        count = len(open(vuln_file).readlines())
        summary.append(f"Vulnerabilities: {count}")
    
    summary.append(f"Waktu scan: {time.strftime('%Y-%m-%d %H:%M:%S')}")
    
    return "\n".join(summary)

def read_config(config_file):
    default_config = {
        "discord_webhook_url": "",
        "telegram_bot_token": "",
        "telegram_chat_id": "",
        "threads": 5,
        "rate_limit": 750
    }
    
    if not os.path.exists(config_file):
        logging.warning(f"{Colors.YELLOW}File konfigurasi {config_file} tidak ditemukan. Menggunakan default.{Colors.RESET}")
        return default_config
    
    try:
        with open(config_file, 'r') as f:
            config = json.load(f)
        
        for key in default_config:
            if key not in config:
                config[key] = default_config[key]
                logging.warning(f"{Colors.YELLOW}Konfigurasi {key} tidak ditemukan. Menggunakan default.{Colors.RESET}")
        
        return config
    except Exception as e:
        logging.error(f"{Colors.RED}Error saat membaca konfigurasi: {e}. Menggunakan default.{Colors.RESET}")
        return default_config

def process_domain(target):
    os.system('cls' if os.name == 'nt' else 'clear')
    
    start_time = time.time()
    logging.info(f"{Colors.CYAN}===== Memulai pemrosesan untuk target: {target} ====={Colors.RESET}")
    
    try:
        create_directories(target)
        
        check_dependencies()
        
        run_subfinder(target)
        run_assetfinder(target)
        
        run_dnsx(target)
        
        run_http_probe(target)
        
        if args.screenshot:
            run_screenshots(target)
        
        if args.port_scan:
            run_port_scan(target)
        
        extract_wayback_urls(target)
        validate_urls(target)
        find_js_files(target)
        
        if args.nuclei:
            run_nuclei(target)
        
        send_to_discord(target)
        
        delete_empty_directories(target)
        
        execution_time = time.time() - start_time
        logging.info(f"{Colors.CYAN}===== Pemrosesan selesai untuk {target} dalam {execution_time:.2f} detik ====={Colors.RESET}")
        
        summary = create_summary(target)
        summary_file = f"{target}/summary.txt"
        with open(summary_file, 'w') as f:
            f.write(f"Target: {target}\n")
            f.write(f"Waktu eksekusi: {execution_time:.2f} detik\n")
            f.write("=== Ringkasan ===\n")
            f.write(summary)
        
        logging.info(f"{Colors.GREEN}Ringkasan tersimpan di {summary_file}{Colors.RESET}")
    
    except Exception as e:
        logging.error(f"{Colors.RED}Error selama pemrosesan {target}: {e}{Colors.RESET}")
        import traceback
        logging.error(traceback.format_exc())

def main():
    logger = setup_logging()
    
    print_banner()
    
    parser = argparse.ArgumentParser(
        description="JST-Stunner - Tool untuk menemukan file JS, endpoint API, dan kerentanan pada domain",
        formatter_class=argparse.RawTextHelpFormatter
    )
    
    parser.add_argument('-t', '--target', type=str, help='Target domain/IP/CIDR tunggal untuk di-scan')
    parser.add_argument('-l', '--list', type=str, help='File berisi daftar target untuk di-scan')
    parser.add_argument('--threads', type=int, default=5, help='Jumlah thread yang digunakan untuk pemindaian paralel (default: 5)')
    parser.add_argument('--screenshot', action='store_true', help='Aktifkan pengambilan screenshot')
    parser.add_argument('--nuclei', action='store_true', help='Aktifkan pemindaian Nuclei')
    parser.add_argument('--port-scan', action='store_true', help='Aktifkan pemindaian port')
    parser.add_argument('--config', type=str, default='config.json', help='Path ke file konfigurasi (default: config.json)')
    parser.add_argument('--output-dir', type=str, help='Direktori untuk menyimpan hasil (default: direktori saat ini)')
    
    global args
    args = parser.parse_args()
    
    if args.output_dir:
        if not os.path.exists(args.output_dir):
            os.makedirs(args.output_dir, exist_ok=True)
        os.chdir(args.output_dir)
    
    if args.target:
        target = args.target
        if validate_input(target):
            try:
                process_domain(target)
            except KeyboardInterrupt:
                logging.warning(f"{Colors.YELLOW}Pemindaian dibatalkan oleh pengguna.{Colors.RESET}")
                sys.exit(1)
    elif args.list:
        file_path = args.list
        if os.path.isfile(file_path):
            with open(file_path, 'r') as file:
                targets = [line.strip() for line in file.readlines() if line.strip() and not line.strip().startswith('#')]
            
            total_targets = len(targets)
            logging.info(f"{Colors.BLUE}Akan memproses {total_targets} target dari {file_path}{Colors.RESET}")
            
            try:
                with concurrent.futures.ThreadPoolExecutor(max_workers=args.threads) as executor:
                    futures = []
                    with tqdm(total=total_targets) as pbar:
                        for i, target in enumerate(targets, 1):
                            if validate_input(target):
                                futures.append(executor.submit(process_domain, target))
                            pbar.update(1)
                        
                        for future in concurrent.futures.as_completed(futures):
                            try:
                                future.result()
                            except Exception as e:
                                logging.error(f"{Colors.RED}Error dalam thread: {e}{Colors.RESET}")
                
                logging.info(f"{Colors.GREEN}Semua pemindaian selesai!{Colors.RESET}")
            except KeyboardInterrupt:
                logging.warning(f"{Colors.YELLOW}Pemindaian dibatalkan oleh pengguna.{Colors.RESET}")
                sys.exit(1)
        else:
            logging.error(f"{Colors.RED}File yang diberikan tidak ada atau tidak valid.{Colors.RESET}")
    else:
        logging.error(f"{Colors.RED}Harap berikan domain tunggal (-t) atau daftar domain (-l) atau (-h) untuk bantuan{Colors.RESET}")
        parser.print_help()

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print(f"\n{Colors.YELLOW}Program dibatalkan oleh pengguna.{Colors.RESET}")
    except Exception as e:
        print(f"{Colors.RED}Terjadi kesalahan tak terduga: {e}{Colors.RESET}")
        import traceback
        traceback.print_exc()
