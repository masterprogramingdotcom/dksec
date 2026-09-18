# 🛡️ DKSec — The All-in-One Security Platform

[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![Python 3.10+](https://img.shields.io/badge/Python-3.10%2B-brightgreen.svg)](https://python.org)

**Welcome to DKSec!** 
Whether you are a developer, a security researcher, or a DevOps engineer, keeping your applications secure shouldn't require juggling 10 different tools. 

**DKSec** is a unified platform that automatically scans your code, tests your live websites, finds vulnerabilities, and even tells you exactly how to fix them—all in one place.

---

## 🌟 What makes DKSec special?

Instead of running separate tools for your code, your APIs, and your dependencies, DKSec does it all. Here is what it can do for you in plain English:

1. **🕵️ Live Website & API Testing (DAST):** It actively attacks your live application (safely!) to find issues like SQL Injection, Cross-Site Scripting (XSS), and hidden API bugs.
2. **🔐 Role Testing (BOLA/IDOR):** You can give it an "Admin" token and a "Normal User" token. DKSec will automatically check if the normal user can sneakily access admin data!
3. **💻 Code Scanning (SAST):** It reads your source code to find hardcoded passwords, secret keys, and dangerous code patterns before you even deploy.
4. **🤖 AI-Powered Fixes:** When it finds a bug, it uses AI (like ChatGPT or Claude) to explain the issue and even writes the code patch for you!
5. **🔔 Instant Alerts:** It can send a summary of your security scan directly to your Slack, Discord, or Microsoft Teams channel.
6. **📊 Beautiful Dashboard:** You don't have to read messy terminal logs. DKSec gives you a stunning, interactive Web UI to review your security health.

---

## 🚀 Getting Started

Setting up DKSec is incredibly easy. It will automatically detect if you are on Linux, macOS, or Windows and set everything up for you.

### 1. Installation

**For Linux & macOS users:**
```bash
# 1. Clone this repository (if you haven't already)
git clone https://github.com/masterprogramingdotcom/dksec.git
cd dksec

# 2. Run the automatic setup command
make setup

# 3. Activate the environment
source .venv/bin/activate
```

**For Windows users:**
Open your PowerShell and run:
```powershell
# 1. Clone and enter the folder
git clone https://github.com/masterprogramingdotcom/dksec.git
cd dksec

# 2. Set up Python manually
python -m venv .venv
.venv\Scripts\activate
pip install -r requirements.txt
pip install -e .
```

---

## 🎮 How to Use DKSec

Once installed, you can interact with DKSec in a few different ways depending on what you prefer!

### Option A: The Web Dashboard (Easiest)
Want to click buttons instead of typing commands? Start the visual dashboard:
```bash
make ui
```
*Open your browser and go to `http://127.0.0.1:8080` to start scanning from a beautiful interface!*

### Option B: The Terminal Wizard
Not sure what command to run? Let the interactive wizard guide you step-by-step:
```bash
python3 dksec.py wizard
```

### Option C: Quick CLI Commands
If you want to run quick scans directly from your terminal, here are the most common commands:

**1. Scan a live website:**
```bash
python3 dksec.py scan --url https://yourwebsite.com --preset api
```

**2. Test if regular users can steal admin data (Dual-Session):**
```bash
python3 dksec.py scan --url https://api.yoursite.com --token "admin_jwt_here" --user-b-token "regular_user_jwt_here"
```

**3. Run a scan and send the results to Slack:**
```bash
python3 dksec.py scan --url https://yourwebsite.com --webhook-url "https://hooks.slack.com/services/..."
```

**4. Compare today's scan against yesterday's (Delta Diffing):**
```bash
# Did we fix the bugs, or create new ones?
python3 dksec.py scan -s 4 --diff-against previous-report.json
```

---

## 📂 What do you get at the end of a scan?
When DKSec finishes scanning, it places all your reports inside the `./reports/` folder. You will find:
* **Interactive HTML Report** (`dksec-report.html`): Open this in your browser to see interactive findings, including copy-pasteable `cURL` commands to reproduce the hacks.
* **Diff Patches** (`dksec-diff.json`): Ready-to-merge code fixes for the vulnerabilities it found.
* **Machine Reports** (SARIF & SBOM): Files used by compliance teams and GitHub/GitLab to track your security health.

---

## 🛡️ License
Released under the MIT License. Built to make DevSecOps simple for everyone.
