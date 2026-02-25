<table>
  <tr>
    <td><img src="assets/hunterTraceLogo.png" alt="HunterTrace Logo" width="120" /></td>
    <td>
      <h1>Geo Location Analyzer and Attacker Identification System</h1>
    </td>
  </tr>
</table>

## Overview
This project is a comprehensive attacker identification and attribution system for forensic analysis of email threats. It traces real attacker IPs, detects VPN/proxy obfuscation, and provides campaign correlation and reporting.

---

## Installation

### 1. Clone the Repository (if needed)
```
git clone https://github.com/akshaydotweb/HunterTrace.git
cd HunterTrace
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


### 4. Configure ABUSEIPDB API Key

**Create a `.env` file in the project root directory to securely store your ABUSEIPDB API key.**

1. In the root of your project, create a file named `.env` (if it does not exist).
2. Add the following line to the `.env` file, replacing `your_abuseipdb_api_key_here` with your actual API key:

  ```
  ABUSEIPDB_API_KEY=your_abuseipdb_api_key_here
  ```

You can obtain a free API key by signing up at [AbuseIPDB](https://www.abuseipdb.com/).

> **Note:** The `.env` file is used to keep sensitive information out of your codebase. Never share your API key publicly.

---

## Usage



## Project Structure

- `src/` — Main source code
- `docs/` — Documentation and guides
- `assets/` — Images and logos

---

## Usage

### Single Email Analysis
```
python src/hunterTrace.py path/to/email.eml
```

### Batch Email Analysis (Directory)
```
python src/hunterTrace.py batch path/to/email_directory/
```


### Info/Help
```
python src/hunterTrace.py info
```


### Export JSON Report
```
python src/hunterTrace.py path/to/email.eml --json report.json
```

---

## Demo



### Example: Analyze a Single Email
```
python src/hunterTrace.py samples/acme_corp_corporate_phishing.eml
```

### Example: Batch Process All Emails in a Directory
```
python src/hunterTrace.py batch samples/
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
