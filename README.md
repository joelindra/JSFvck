# JStunner

JStunner adalah alat rekognisi JavaScript untuk menemukan file JS, API endpoint, dan kerentanan keamanan pada domain target. Alat ini dirancang untuk membantu pengujian penetrasi dan bug bounty hunter dalam mengidentifikasi potensial kerentanan.

## Fitur

- **Pencarian Subdomain** - Menemukan subdomain menggunakan `subfinder` dan `assetfinder`
- **Resolusi DNS** - Menggunakan `dnsx` untuk mendapatkan informasi DNS dari subdomain
- **HTTP Probing** - Mengidentifikasi host HTTP/HTTPS aktif menggunakan `httprobe`
- **Wayback URL** - Mengekstrak URL dari arsip Wayback Machine
- **Pencarian JavaScript** - Menemukan file JavaScript dan mengekstrak secret dengan `secretfinder`
- **Fitur Opsional:**
  - **Pengambilan Screenshot** - Mengambil screenshot dari host aktif menggunakan `gowitness`
  - **Pemindaian Port** - Menemukan port terbuka menggunakan `nmap`
  - **Deteksi Kerentanan** - Menemukan kerentanan menggunakan `nuclei`

## Prasyarat

JStunner membutuhkan beberapa tool untuk dijalankan dengan baik. Tool-tool ini dapat diinstal secara manual atau melalui manajer paket seperti apt, brew, dll.

- subfinder
- assetfinder
- httprobe
- waybackurls
- ffuf
- secretfinder
- gau
- dnsx
- gowitness (opsional)
- nmap (opsional)
- nuclei (opsional)

## Instalasi

1. Clone repositori ini:
```bash
git clone https://github.com/joelindra/jstunner.git
cd jstunner
```

2. Instal dependensi Python:
```bash
pip install -r requirements.txt
```

3. Pastikan semua tool external terinstal dan dapat diakses melalui PATH.

## Penggunaan

### Perintah Dasar

Untuk memindai satu domain (hanya pencarian JS):

```bash
python jstunner.py -t example.com
```

Untuk memindai multiple domain dari file:

```bash
python jstunner.py -l domains.txt
```

### Opsi Tambahan

Aktifkan pengambilan screenshot:

```bash
python jstunner.py -t example.com --screenshot
```

Aktifkan pemindaian port:

```bash
python jstunner.py -t example.com --port-scan
```

Aktifkan pemindaian kerentanan dengan Nuclei:

```bash
python jstunner.py -t example.com --nuclei
```

Kombinasikan beberapa opsi:

```bash
python jstunner.py -t example.com --screenshot --port-scan --nuclei
```

Sesuaikan jumlah thread:

```bash
python jstunner.py -t example.com --threads 10
```

### Semua Opsi

```
usage: jstunner.py [-h] [-t TARGET] [-l LIST] [--threads THREADS]
                   [--screenshot] [--nuclei] [--port-scan]
                   [--config CONFIG] [--output-dir OUTPUT_DIR]

JStunner - Tool untuk menemukan file JS, endpoint API, dan kerentanan pada domain

optional arguments:
  -h, --help            show this help message and exit
  -t TARGET, --target TARGET
                        Target domain/IP/CIDR tunggal untuk di-scan
  -l LIST, --list LIST  File berisi daftar target untuk di-scan
  --threads THREADS     Jumlah thread yang digunakan untuk pemindaian paralel (default: 5)
  --screenshot          Aktifkan pengambilan screenshot
  --nuclei              Aktifkan pemindaian Nuclei
  --port-scan           Aktifkan pemindaian port
  --config CONFIG       Path ke file konfigurasi (default: config.json)
  --output-dir OUTPUT_DIR
                        Direktori untuk menyimpan hasil (default: direktori saat ini)
```

## Konfigurasi

JStunner dapat dikonfigurasikan melalui file `config.json`. Contoh konfigurasi:

```json
{
  "discord_webhook_url": "https://discord.com/api/webhooks/your-webhook-url",
  "telegram_bot_token": "your-telegram-bot-token",
  "telegram_chat_id": "your-telegram-chat-id",
  "threads": 5,
  "rate_limit": 750
}
```

## Struktur Hasil

Hasil pemindaian disimpan dalam direktori yang dinamai sesuai domain target, dengan struktur sebagai berikut:

```
target.com/
├── sources/
│   ├── subfinder.txt
│   ├── assetfinder.txt
│   └── all.txt
├── result/
│   ├── httpx/
│   ├── wayback/
│   ├── js/
│   ├── endpoints/
│   ├── dns/
│   ├── screenshots/ (jika diaktifkan)
│   ├── ports/ (jika diaktifkan)
│   └── nuclei/ (jika diaktifkan)
└── summary.txt
```

## Penanganan Error

JStunner mencatat semua aktivitas ke dalam file log di direktori `logs/`. Log ini berguna untuk debugging dan melacak kemajuan pemindaian.

## Lisensi

Fork to contribute!

## Keamanan

Tool ini hanya boleh digunakan pada sistem atau domain yang Anda miliki izin untuk mengujinya. Penggunaan pada sistem tanpa izin dapat melanggar hukum.

## Lisensi

Copyright (c) 2025 Joel Indra. All rights reserved.
Unauthorized copying, distribution, or modification is prohibited without explicit permission.

![image](https://github.com/user-attachments/assets/c77f46bf-a8b6-4d9e-b9f8-35b33904245e)


