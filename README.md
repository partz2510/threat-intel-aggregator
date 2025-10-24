# 🕵️‍♂️ Threat Intel Aggregator (Python + API Integration)

A real-time **cyber threat intelligence CLI tool** that queries multiple public intelligence sources — **VirusTotal**, **AbuseIPDB**, and **AlienVault OTX** — to assess the reputation and threat profile of any given IP address, domain, or file hash.

This project showcases **API integration**, **secure key management**, **threat correlation**, and **command-line reporting** using Python.  
Designed for security analysts, SOC teams, and anyone interested in automating threat reputation checks.

---

## 🚀 Features

✅ **Multi-source lookups** — Combines results from VirusTotal, AbuseIPDB, and OTX.  
✅ **Secure key management** — Uses environment variables via `.env` (no hardcoded secrets).  
✅ **Rich CLI reporting** — Beautiful color-coded tables via the `rich` library.  
✅ **JSON Report Export** — Saves all results for offline review or SIEM ingestion.  
✅ **Timeout & Error Handling** — Gracefully handles rate limits, 404s, and timeouts.  
✅ **Cross-Platform** — Works on Windows, macOS, and Linux.  
✅ **Zero external dependencies besides `requests`, `dotenv`, and `rich`.**

---

## 🧰 Tech Stack

| Category | Tools |
|-----------|--------|
| Language | Python 3.10+ |
| Libraries | `requests`, `rich`, `python-dotenv`, `json`, `argparse` |
| Output | JSON, colorized CLI table |
| Security | SHA256 for file hash validation (planned) |

---

## ⚙️ Setup & Usage

### 1️⃣ Clone the Repository
```bash
git clone https://github.com/<your-username>/threat-intel-aggregator.git
cd threat-intel-aggregator
2️⃣ Create a Virtual Environment
bash
Copy code
python -m venv .venv
.\.venv\Scripts\Activate.ps1   # Windows
# or
source .venv/bin/activate      # macOS/Linux
3️⃣ Install Requirements
bash
Copy code
pip install -r requirements.txt
4️⃣ Create a .env File in the Project Root
bash
Copy code
VT_API_KEY=your_virustotal_api_key
ABUSEIPDB_KEY=your_abuseipdb_api_key
OTX_API_KEY=your_otx_api_key
🔐 Never commit your .env file to GitHub — it’s already ignored in .gitignore.

🧠 Example Usage
Basic Query
bash
Copy code
python src/main.py 8.8.8.8 --save
🧾 Example Output
When run successfully, the tool aggregates live intelligence from all three APIs and displays a colorized summary in your terminal:

nginx
Copy code
               Threat Intel | 8.8.8.8
┏━━━━━━━━━━━━┳━━━━━━━━┳━━━━━━━━━━━━━━━━━━━━━━━━┓
┃ Source     ┃ Status ┃ Summary                ┃
┡━━━━━━━━━━━━╇━━━━━━━━╇━━━━━━━━━━━━━━━━━━━━━━━━┩
│ VirusTotal │ OK     │ reputation=526         │
│ AbuseIPDB  │ OK     │ abuseConfidenceScore=0 │
│ OTX        │ OK     │ pulses=0               │
└────────────┴────────┴────────────────────────┘
Saved report: reports\report-8.8.8.8.json
And here’s a screenshot of the actual output captured from the live run:


(Replace the placeholder above with your own screenshot — taken directly from your terminal window.)

📁 Folder Structure
css
Copy code
threat-intel-aggregator/
├── src/
│   ├── main.py
│   ├── services.py
├── reports/
│   ├── report-8.8.8.8.json
├── .env
├── .gitignore
├── requirements.txt
├── README.md
└── Screenshot/
    ├── report status.png (CLI output screenshot)
🧩 Future Improvements
Add domain & file hash reputation support.

Integrate additional feeds (Shodan, GreyNoise, Hybrid Analysis).

Export reports directly to Splunk or Elasticsearch.

Add auto-update scheduling.

✨ Author
Parthiban Ganesan
📍 Singapore | 💼 Cybersecurity & Cloud Enthusiast
🔗 LinkedIn | GitHub

📜 License
MIT License — free for educational and professional use.