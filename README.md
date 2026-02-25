# Complete Attacker Identification System

## Overview
This project is a comprehensive attacker identification and attribution system for forensic analysis of email threats. It traces real attacker IPs, detects VPN/proxy obfuscation, and provides campaign correlation and reporting.

---

## Installation

### 1. Clone the Repository (if needed)
```
git clone <your-repo-url>
cd ProjectPhase2
```

### 2. Create and Activate a Virtual Environment (Recommended)
```
python3 -m venv .venv
source .venv/bin/activate
```

### 3. Install Dependencies
```
pip install -r requirements.txt
```

---

## Usage


### Single Email Analysis
```
python hunterTrace.py path/to/email.eml
```

### Batch Email Analysis (Directory)
```
python hunterTrace.py batch path/to/email_directory/
```

### Info/Help
```
python hunterTrace.py info
```

### Export JSON Report
```
python hunterTrace.py path/to/email.eml --json report.json
```

---

## Demo


### Example: Analyze a Single Email
```
python hunterTrace.py mails/sample_email.eml
```

### Example: Batch Process All Emails in a Directory
```
python hunterTrace.py batch mails/
```

### Example Output
- The system will print a detailed report to the console, including:
  - Proxy chain tracing
  - VPN/proxy detection
  - Real attacker location (if possible)
  - Campaign correlation (batch mode)
  - JSON export (if specified)

---

## Requirements
- Python 3.7+
- See `requirements.txt` for dependencies

---

## Troubleshooting
- If you see missing package errors, ensure your virtual environment is activated and run `pip install -r requirements.txt` again.
- For geolocation to work, ensure you have internet access for API lookups.

---

## License
This project is for educational and research purposes. See LICENSE for details.
