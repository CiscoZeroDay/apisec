# 🔧 APISEC — Installation and Configuration Guide

> **Version:** 2.0 | **Author:** RAZAFINDRAIBE Hery Jhonny | **ENSAT Tanger / DATAPROTECT Casablanca**

---

## 📋 Table of Contents

1. [Prerequisites](#prerequisites)
2. [Installation on Windows](#installation-on-windows)
3. [Installation on Linux (Kali / Ubuntu)](#installation-on-linux-kali--ubuntu)
4. [Installing Optional Security Tools](#installing-optional-security-tools)
5. [Configuration](#configuration)
6. [Verifying the Installation](#verifying-the-installation)
7. [Troubleshooting](#troubleshooting)

---

## 1. ✅ Prerequisites

Before installing APISEC, ensure the following are available on your system :

| Requirement | Minimum Version | Notes |
|---|---|---|
| Python | 3.11+ (3.13 recommended) | Must be in PATH |
| pip | Latest | Comes with Python |
| Git | Any | For cloning the repository |
| sqlmap | Latest | Required for SQL injection tests |
| mitmproxy | 11.x | Required for traffic capture |

> ⚠️ **sqlmap** and **mitmproxy** are optional — APISEC works without them but SQL injection and traffic capture features will be unavailable.

---

## 2. 🪟 Installation on Windows

### Step 1 — Install Python 3.13

1. Download Python 3.13 from https://www.python.org/downloads/
2. Run the installer
3. ✅ **Check "Add Python to PATH"** before clicking Install
4. Verify installation :

```cmd
python --version
# Expected: Python 3.13.x
```

### Step 2 — Clone the repository

```cmd
git clone https://github.com/CiscoZeroDay/apisec.git
cd apisec
```

### Step 3 — Install Python dependencies

```cmd
pip install -r requirements.txt
```

Expected output :
```
Successfully installed flask certifi charset-normalizer requests reportlab urllib3
```

### Step 4 — Install sqlmap (optional but recommended)

```cmd
git clone https://github.com/sqlmapproject/sqlmap.git C:\tools\sqlmap
```

Add `C:\tools\sqlmap` to your system PATH :
- Windows Search → "Environment Variables"
- System Variables → Path → Edit → New → `C:\tools\sqlmap`

Verify :
```cmd
sqlmap --version
```

### Step 5 — Install mitmproxy (optional)

```cmd
pip install mitmproxy mitmproxy2swagger pyyaml
```

Verify :
```cmd
mitmdump --version
```

### Step 6 — Launch the Web UI

```cmd
python web_app.py
```

Open your browser at : **http://localhost:5000**

### Step 7 — Or use the CLI directly

```cmd
python main.py --help
```

---

## 3. 🐧 Installation on Linux (Kali / Ubuntu)

### Step 1 — Update system packages

```bash
sudo apt update && sudo apt upgrade -y
```

### Step 2 — Install Python 3.13

**Kali Linux / Ubuntu 24.04+ :**
```bash
sudo apt install python3.13 python3.13-pip python3.13-venv -y
```

**Ubuntu 22.04 (manual install) :**
```bash
sudo add-apt-repository ppa:deadsnakes/ppa
sudo apt update
sudo apt install python3.13 python3.13-pip -y
```

Verify :
```bash
python3.13 --version
# Expected: Python 3.13.x
```

### Step 3 — Clone the repository

```bash
git clone https://github.com/CiscoZeroDay/apisec.git
cd apisec
```

### Step 4 — Create a virtual environment (recommended)

```bash
python3.13 -m venv venv
source venv/bin/activate
```

### Step 5 — Install Python dependencies

```bash
pip install -r requirements.txt
```

### Step 6 — Install sqlmap (optional)

**Kali Linux** (already included) :
```bash
sqlmap --version
```

**Ubuntu** :
```bash
sudo apt install sqlmap -y
# OR latest version:
git clone https://github.com/sqlmapproject/sqlmap.git ~/tools/sqlmap
echo 'alias sqlmap="python3 ~/tools/sqlmap/sqlmap.py"' >> ~/.bashrc
source ~/.bashrc
```

### Step 7 — Install mitmproxy (optional)

```bash
pip install mitmproxy mitmproxy2swagger pyyaml
```

Verify :
```bash
mitmdump --version
```

### Step 8 — Launch the Web UI

```bash
python web_app.py
```

Open your browser at : **http://localhost:5000**

### Step 9 — Or use the CLI directly

```bash
python main.py --help
```

---

## 4. 🛠️ Installing Optional Security Tools

### Clairvoyance (GraphQL schema recovery)

Clairvoyance is bundled inside the `wordlists/` directory — no installation required. APISEC uses it automatically when GraphQL introspection is disabled.

### dalfox (XSS detection — planned)

```bash
# Linux
go install github.com/hahwul/dalfox/v2@latest

# Windows
# Download binary from https://github.com/hahwul/dalfox/releases
```

---

## 5. ⚙️ Configuration

### AI Assistant (optional)

APISEC supports two AI providers for scan analysis. Configure via environment variables :

**Groq (free — recommended) :**
```bash
# Linux
export APISEC_AI_PROVIDER=groq
export GROQ_API_KEY=gsk_your_key_here

# Windows
set APISEC_AI_PROVIDER=groq
set GROQ_API_KEY=gsk_your_key_here
```

Get a free Groq API key at : https://console.groq.com

**Ollama (fully local, no internet) :**
```bash
# Install Ollama first: https://ollama.com
ollama pull llama3.2

export APISEC_AI_PROVIDER=ollama
export OLLAMA_MODEL=llama3.2
```

**Switch to a more powerful model :**
```bash
# Groq — more powerful free model
export GROQ_MODEL=llama-3.3-70b-versatile

# Ollama — local powerful model
ollama pull mistral
export OLLAMA_MODEL=mistral
```

### Custom timeout

```bash
# Increase timeout for slow targets
python main.py full --url https://target.com --timeout 15
```

---

## 6. ✔️ Verifying the Installation

Run the following commands to verify everything is working :

```bash
# 1. Check APISEC CLI
python main.py --help

# 2. Check Web UI starts correctly
python web_app.py
# Expected: * Running on http://127.0.0.1:5000

# 3. Check sqlmap integration
python main.py scan --url http://localhost --tests sqli --list-tests

# 4. Quick test scan against a safe target
python main.py discovery --url https://httpbin.org --wordlist wordlists/swagger.txt
```

---

## 7. 🔧 Troubleshooting

### ❌ `ModuleNotFoundError: No module named 'flask'`
```bash
pip install -r requirements.txt
```

### ❌ `sqlmap: command not found`
Ensure sqlmap is in your PATH. See Step 4 above.

### ❌ Web UI shows blank page
```bash
# Check Flask is running
python web_app.py
# Then open: http://localhost:5000
```

### ❌ `mitmproxy: SSL certificate error`
```bash
# Run mitmproxy once to generate the certificate
mitmdump --quiet &
sleep 3 && kill %1
# Then install the certificate:
# Windows: certutil -addstore -user ROOT ~/.mitmproxy/mitmproxy-ca-cert.cer
# Linux: sudo cp ~/.mitmproxy/mitmproxy-ca-cert.pem /usr/local/share/ca-certificates/mitmproxy-ca.crt && sudo update-ca-certificates
```

### ❌ Port 5000 already in use
```bash
# Use a different port
python web_app.py --port 8080
# Or kill the process using port 5000
# Linux: kill $(lsof -t -i:5000)
# Windows: netstat -ano | findstr :5000 → taskkill /PID <PID> /F
```

---

*Installation Guide — APISEC v2.0 | ENSAT Tanger / DATAPROTECT Casablanca 2026*
