
# JStuner

JStunner is a tool designed for discovering JavaScript files and secrets within domains. It automates the process of scanning domains by using various tools like `subfinder`, `assetfinder`, `httprobe`, `waybackurls`, and `ffuf` to gather information and validate URLs.

## Features
- Scan single or multiple domains for subdomains.
- Probe HTTP services to find active URLs.
- Extract URLs from the Wayback Machine.
- Validate Wayback URLs.
- Find and extract JavaScript files from Wayback URLs.
- Send scan results and files via Telegram.

## Requirements
- Python 3.x
- Subfinder
- Assetfinder
- Httprobe
- Waybackurls
- ffuf
- secretfinder.py (for finding secrets in JS files) must installed on system (/usr/bin)
- Telegram bot (for sending results)

## Installation

Clone this repository:

```bash
git clone https://github.com/joelindra/JStunner.git
cd JStunner
```

Install required Python libraries:

```bash
pip install -r requirements.txt
```

## Usage

### Scan a single domain:

```bash
python3 jstunner.py -t example.com
```

### Scan a list of domains from a file:

```bash
python3 jstunner.py -l domains.txt
```

Where `domains.txt` is a text file with one domain per line.

## Configuration

Before using the Telegram notification feature, create a `config.json` file with the following format:

```json
{
    "telegram_token": "your-telegram-bot-token",
    "telegram_chat_id": "your-chat-id"
}
```

## Logging

All logs will be saved in `scan.log`, with a rotation mechanism in place to keep log files manageable.

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## Author

- Joel Indra

Feel free to contribute to the project!

