# JSFvck

**JSFvck** is a powerful and automated reconnaissance tool designed for security researchers and penetration testers. It streamlines the process of discovering subdomains, probing HTTP servers, extracting URLs from the Wayback Machine, validating URLs, and identifying JavaScript files, API endpoints, and potential secrets. Built with Python and leveraging popular open-source tools, JSFvck provides a comprehensive and user-friendly solution for web reconnaissance.

## Features

- **Subdomain Enumeration**: Discovers subdomains using tools like `subfinder` and `assetfinder`.
- **DNS Resolution**: Resolves subdomains with `dnsx` to identify valid hosts.
- **HTTP Probing**: Probes for active HTTP servers using `httprobe`.
- **Wayback URL Extraction**: Extracts historical URLs from the Wayback Machine with `waybackurls` and `gau`.
- **URL Validation**: Validates extracted URLs using `ffuf` to ensure they are accessible.
- **JavaScript Analysis**: Identifies `.js` files, extracts API endpoints with `hakrawler`, and searches for secrets using `secretfinder`.
- **Structured Output**: Organizes results into a clean directory structure for easy analysis.
- **Rich Console Output**: Utilizes the `rich` library for visually appealing terminal output, including banners, progress bars, and summary tables.
- **Discord Notifications**: Sends scan summaries and key results to a Discord webhook for real-time updates.
- **Multi-threaded Scanning**: Supports parallel scanning of multiple targets for efficiency.
- **Configurable**: Customizable via a JSON configuration file for webhook URLs, thread count, and more.

## Installation

### Prerequisites
Ensure the following tools are installed on your system:
- `subfinder`
- `assetfinder`
- `httprobe`
- `waybackurls`
- `ffuf`
- `gau`
- `dnsx`
- `httpx`
- `hakrawler`
- Python packages: `pyfiglet`, `rich`, `requests`

You can install the Python dependencies using:
```bash
pip install -r requirements.txt
```

### Clone the Repository
```bash
git clone https://github.com/Anonre/JSFvck.git
cd JSFvck
```

### Install Dependencies
```bash
pip install pyfiglet rich requests
```

## Usage

JSFvck can be run with a single target or a list of targets. Below are the available command-line arguments:

```bash
python jsfvck.py -t <target>                # Scan a single domain/IP/CIDR
python jsfvck.py -l <target_list.txt>      # Scan multiple targets from a file
python jsfvck.py --threads 5               # Set the number of threads (default: 5)
python jsfvck.py --config config.json      # Specify a custom config file
python jsfvck.py --output-dir results      # Save results to a custom directory
```

### Example Commands
- Scan a single domain:
  ```bash
  python jsfvck.py -t example.com
  ```

- Scan multiple targets from a file:
  ```bash
  python jsfvck.py -l targets.txt --threads 10
  ```

- Save results to a specific directory:
  ```bash
  python jsfvck.py -t example.com --output-dir scan_results
  ```

### Configuration
Create a `config.json` file to customize settings, such as Discord webhook URL, Telegram bot token, and thread count. Example:

```json
{
  "discord_webhook_url": "https://discord.com/api/webhooks/...",
  "telegram_bot_token": "",
  "telegram_chat_id": "",
  "threads": 5,
  "rate_limit": 750
}
```

## Output Structure
Results are organized in a structured directory for each target:
```
target/
├── sources/
│   ├── subfinder.txt
│   ├── assetfinder.txt
│   ├── all.txt
├── result/
│   ├── dns/
│   │   ├── resolved.txt
│   ├── httpx/
│   │   ├── httpx.txt
│   ├── wayback/
│   │   ├── wayback.txt
│   │   ├── valid.txt
│   ├── js/
│   │   ├── js.txt
│   │   ├── secret.txt
│   ├── endpoints/
│   │   ├── api_endpoints.txt
└── logs/
    ├── scan_<timestamp>.log
```

## Logging
Logs are stored in the `logs/` directory with timestamps and rotate automatically to manage disk space. Logs include detailed information about the scanning process, errors, and results.

## Contributing
Contributions are welcome! Feel free to submit pull requests, report bugs, or suggest features via GitHub issues.

## License
This project is licensed under the MIT License. See the `LICENSE` file for details.

## Disclaimer
JSFvck is intended for authorized security testing and research purposes only. Unauthorized use on systems you do not own or have explicit permission to test is illegal and prohibited.

## Author
**Anonre**  
Feel free to reach out for collaboration or feedback!
