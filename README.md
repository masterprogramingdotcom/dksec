# 🛡️ DKSec — Complete Enterprise Security Platform

[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![Python 3.10+](https://img.shields.io/badge/Python-3.10%2B-brightgreen.svg)](https://python.org)

**DKSec** is an enterprise-grade, all-in-one DevSecOps platform. It unifies static source code analysis (SAST), dynamic API and website testing (DAST), multi-role authorization testing (BOLA/IDOR), and auto-remediation into a single, cohesive engine. 

Instead of juggling separate tools for your codebase and live APIs, DKSec orchestrates the entire security lifecycle automatically.

---

## ✨ Core Capabilities

* **Static Code Scanning (SAST & SCA):** Scans your source code for hardcoded secrets, SQL injection, RCE, and generates Software Bill of Materials (SBOMs).
* **Live API & Web Testing (DAST):** Actively probes running applications for vulnerabilities, missing CORS policies, and server misconfigurations.
* **Active Fuzzing:** Automatically parses OpenAPI/Swagger specifications and injects payloads (XSS, Path Traversal) into dynamic endpoints.
* **Dual-Session RBAC Testing:** Supply an "Admin" token and a "User" token. DKSec will automatically test if the regular user can bypass authorization to access admin data.
* **Delta Regression Diffing:** Compares today's scan with yesterday's scan to highlight exactly what was fixed and what new bugs were introduced.
* **Automated Patch Generation:** Uses AI to generate unified Git Diff patches for the vulnerabilities it finds.

---

## ⚙️ 1. Prerequisites

Before installing DKSec, ensure your system has the following installed:
* **Python 3.10 or higher** (Required for core engine)
* **Git** (Required for cloning the repository)
* **Make** (Optional, but highly recommended for Linux/macOS)

---

## 🛠️ 2. Deep Installation Guide

DKSec runs inside an isolated Python Virtual Environment (`.venv`) to ensure it doesn't conflict with your global system packages. Follow the specific instructions for your Operating System:

### 🐧 Linux (Ubuntu / Debian)
```bash
# 1. Update packages and install prerequisites
sudo apt-get update
sudo apt-get install -y git python3 python3-pip python3-venv make

# 2. Clone the repository
git clone https://github.com/masterprogramingdotcom/dksec.git
cd dksec

# 3. Run the automated setup
make setup

# 4. Activate the virtual environment (Run this every time you open a new terminal)
source .venv/bin/activate
```

### 🍎 macOS
```bash
# 1. Install prerequisites using Homebrew (if not already installed)
brew install python3 make

# 2. Clone the repository
git clone https://github.com/masterprogramingdotcom/dksec.git
cd dksec

# 3. Run the automated setup
make setup

# 4. Activate the virtual environment
source .venv/bin/activate
```

### 🪟 Windows (PowerShell)
```powershell
# 1. Clone the repository (Make sure Git is installed)
git clone https://github.com/masterprogramingdotcom/dksec.git
cd dksec

# 2. Create the Python virtual environment
python -m venv .venv

# 3. Activate the virtual environment (Run this every time you open a new terminal)
.venv\Scripts\activate

# 4. Install dependencies
pip install --upgrade pip
pip install -r requirements.txt
pip install -e .
```

---

## 🚀 3. Comprehensive Usage Guide

DKSec is designed to be highly flexible. You can run it via a Web UI, an interactive terminal wizard, or powerful one-line CLI commands for CI/CD pipelines.

### Option A: The Web UI Dashboard (Recommended for visual users)
Start a local web server to control DKSec directly from your browser.
```bash
# Start the web UI on port 8080
make ui

# If you are on Windows, or prefer the direct python command:
python3 dksec.py ui --port 8080
```
*Open your browser and navigate to `http://127.0.0.1:8080` to view the dashboard and stream live scan results.*

### Option B: The Interactive Terminal Wizard
If you prefer the terminal but don't want to memorize CLI arguments, launch the interactive wizard. It will ask you step-by-step questions about what you want to scan.
```bash
# Using Make:
make wizard

# Using Python directly:
python3 dksec.py wizard
```

### Option C: Advanced CLI Execution (For CI/CD & Automation)
You can bypass the UI and Wizard entirely by passing arguments directly to the scanner. This is perfect for automation scripts.

**1. Basic Live Website Scan:**
```bash
python3 dksec.py scan --url https://your-target.com --preset api
```

**2. Authenticated API Scan (Using a JWT Token):**
If your API requires login, pass the Bearer token directly so DKSec can scan protected endpoints.
```bash
python3 dksec.py scan --url https://api.your-target.com --token "eyJhbGciOiJIUzI1NiIs..." -s 4
```

**3. Dual-Session RBAC / BOLA Testing:**
To test for Broken Object Level Authorization (IDOR), provide an Admin token and a Normal User token. DKSec will check if the normal user can exploit admin privileges.
```bash
python3 dksec.py scan --url https://api.your-target.com --token "ADMIN_JWT" --user-b-token "NORMAL_USER_JWT"
```

**4. Delta Regression Scanning (Diffing):**
Track your security posture over time. Run a scan and compare it against a previous JSON report to see what changed.
```bash
python3 dksec.py scan --url https://your-target.com -s 4 --diff-against ./reports/previous-scan.json
```

**5. Webhook Notifications (Slack / Discord / Teams):**
Automatically dispatch a beautifully formatted JSON summary of your scan results to a webhook URL when the scan finishes.
```bash
python3 dksec.py scan --url https://your-target.com --webhook-url "https://your-webhook.server.local/api/receive"
```

**6. Static Code Analysis (Local Directory):**
Scan a local codebase for secrets and static vulnerabilities (no live URL required).
```bash
python3 dksec.py scan -t /path/to/your/source/code -s sast
```

---

## 🐳 4. Docker Usage
If you prefer not to install Python dependencies on your host machine, you can run the entire DKSec platform inside an isolated Docker container.

```bash
# 1. Build the Docker image
make docker-build

# 2. Run the Web Dashboard inside Docker
make docker-run
```
*The UI will be mapped to `http://127.0.0.1:8080`. Reports will be saved to your local `./reports/` folder via volume mapping.*

---

## 📁 5. Understanding Your Scan Reports

When a scan finishes, DKSec compiles the results into the `./reports/` directory. You will receive several enterprise-standard artifacts:

| File | Purpose |
| :--- | :--- |
| `dksec-report.html` | A highly visual, interactive HTML dashboard. Contains interactive **cURL PoC commands** and raw request/response logs. |
| `dksec-report.json` | The master machine-readable data file used for CI/CD integrations. |
| `dksec-diff.json` | Generated only if `--diff-against` is used. Shows new regressions vs. resolved findings. |
| `cyclonedx-sbom.json` | A standard Software Bill of Materials tracking all your dependencies. |
| `dksec-results.sarif` | Standard SARIF format. Upload this to GitHub Advanced Security or GitLab to see findings inline with your code. |

---

## ❓ Troubleshooting

* **`python3: command not found`**: You need to install Python 3. If you are on Windows, ensure you check the box "Add Python to PATH" during installation.
* **`ModuleNotFoundError: No module named 'dksec'`**: You forgot to activate your virtual environment, or the package wasn't installed. Run `source .venv/bin/activate` (Linux/Mac) or `.venv\Scripts\activate` (Windows), and then run `pip install -e .`.

---

## 🛡️ License
DKSec is released under the MIT License. Built to modernize and unify the DevSecOps lifecycle.
