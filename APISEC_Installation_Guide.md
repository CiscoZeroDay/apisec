# APISec — Installation and Configuration Guide

**Version:** 1.0  
**Author:** RAZAFINDRAIBE Hery Jhonny  
**Repository:** https://github.com/CiscoZeroDay/apisec

---

## Table of Contents

1. Prerequisites
2. Installation on Windows
3. Installation on Linux (Kali / Ubuntu)
4. Installing Optional Tools
5. Configuration
6. Running APISec
7. Verifying the Installation
8. Troubleshooting

---

## 1. Prerequisites

Before installing APISec, ensure the following requirements are met on your system.

| Requirement     | Minimum Version        | Notes                                          |
|-----------------|------------------------|------------------------------------------------|
| Python          | 3.11+ (3.13 recommended) | Must be available in PATH                    |
| pip             | Latest                 | Bundled with Python                            |
| Git             | Any                    | Required for cloning the repository            |
| sqlmap          | Latest                 | Optional — required for SQL injection tests    |
| mitmproxy       | 11.x                   | Optional — required for traffic capture        |

> **Note:** sqlmap and mitmproxy are optional dependencies. APISec operates without them, but SQL injection detection and traffic capture features will be unavailable.

---

## 2. Installation on Windows

### Step 1 — Install Python 3.13

Download the Python 3.13 installer from https://www.python.org/downloads/ and run it.  
Ensure the option **"Add Python to PATH"** is checked before proceeding with the installation.

Verify the installation:

```
python --version
```

Expected output: `Python 3.13.x`

### Step 2 — Clone the Repository

```
git clone https://github.com/CiscoZeroDay/apisec.git
cd apisec
```

### Step 3 — Create a Virtual Environment

Creating a virtual environment is recommended to isolate APISec dependencies from the global Python installation.

```
python -m venv venv
venv\Scripts\activate
```

### Step 4 — Install Python Dependencies

```
pip install -r requirements.txt
```

### Step 5 — Install APISec as a Global Command

```
pip install -e .
```

This command installs APISec in editable mode using the `setup.py` entry point, making the `apisec` command available globally in the terminal.

Verify:

```
apisec --help
```

### Step 6 — Install sqlmap (Optional)

```
git clone https://github.com/sqlmapproject/sqlmap.git C:\tools\sqlmap
```

Add `C:\tools\sqlmap` to the system PATH:

1. Open Windows Search and type **"Environment Variables"**
2. Under System Variables, select **Path** and click **Edit**
3. Click **New** and enter `C:\tools\sqlmap`

Verify:

```
sqlmap --version
```

### Step 7 — Install mitmproxy (Optional)

```
pip install mitmproxy mitmproxy2swagger pyyaml
```

Verify:

```
mitmdump --version
```

---

## 3. Installation on Linux (Kali / Ubuntu)

### Step 1 — Update System Packages

```
sudo apt update && sudo apt upgrade -y
```

### Step 2 — Install Python 3.13

**Kali Linux / Ubuntu 24.04+:**

```
sudo apt install python3.13 python3.13-pip python3.13-venv -y
```

**Ubuntu 22.04:**

```
sudo add-apt-repository ppa:deadsnakes/ppa
sudo apt update
sudo apt install python3.13 python3.13-pip -y
```

Verify:

```
python3.13 --version
```

Expected output: `Python 3.13.x`

### Step 3 — Clone the Repository

```
git clone https://github.com/CiscoZeroDay/apisec.git
cd apisec
```

### Step 4 — Create a Virtual Environment

```
python3.13 -m venv venv
source venv/bin/activate
```

### Step 5 — Install Python Dependencies

```
pip install -r requirements.txt
```

### Step 6 — Install APISec as a Global Command

```
pip install -e .
```

This command installs APISec in editable mode, making the `apisec` command available globally in the terminal.

Verify:

```
apisec --help
```

### Step 7 — Install sqlmap (Optional)

**Kali Linux** (included by default):

```
sqlmap --version
```

**Ubuntu:**

```
sudo apt install sqlmap -y
```

### Step 8 — Install mitmproxy (Optional)

```
pip install mitmproxy mitmproxy2swagger pyyaml
```

Verify:

```
mitmdump --version
```

---

## 4. Installing Optional Tools

### Clairvoyance — GraphQL Schema Recovery

Clairvoyance is bundled inside the `wordlists/` directory of the repository and requires no separate installation. APISec invokes it automatically when GraphQL introspection is disabled on the target.

---

## 5. Configuration

### AI Assistant (Optional)

APISec integrates an AI-powered assistant for scan result analysis and remediation guidance. Two providers are supported and configured through environment variables.

#### Groq (Free — Recommended)

**Linux:**

```
export APISEC_AI_PROVIDER=groq
export GROQ_API_KEY=gsk_your_key_here
```

**Windows:**

```
set APISEC_AI_PROVIDER=groq
set GROQ_API_KEY=gsk_your_key_here
```

A free Groq API key can be obtained at: https://console.groq.com

To switch to a more powerful model:

```
export GROQ_MODEL=llama-3.3-70b-versatile
```

#### Ollama (Local — No Internet Required)

```
ollama pull llama3.2
export APISEC_AI_PROVIDER=ollama
export OLLAMA_MODEL=llama3.2
```

Install Ollama first at: https://ollama.com

To switch to a different local model:

```
ollama pull mistral
export OLLAMA_MODEL=mistral
```

---

## 6. Running APISec

### CLI Mode

```
apisec --help
apisec discovery --url https://target.com
apisec scan --url https://target.com --tests all
```

### Web Interface Mode

```
python web_app.py
```

Open a browser and navigate to: **http://localhost:5000**

---

## 7. Verifying the Installation

Run the following commands to confirm that all components are correctly installed.

```
# Verify the APISec CLI
apisec --help

# Verify the Web UI starts correctly
python web_app.py
# Expected: * Running on http://127.0.0.1:5000

# Run a quick discovery scan against a safe public target
apisec discovery --url https://httpbin.org
```

---

## 8. Troubleshooting

### ModuleNotFoundError: No module named 'flask'

```
pip install -r requirements.txt
```

### sqlmap: command not found

Ensure sqlmap is added to your system PATH. Refer to Step 6 of the installation guide for your operating system.

### Web UI shows a blank page

```
python web_app.py
```

Then open: http://localhost:5000

### mitmproxy SSL certificate error

**Linux:**

```
sudo cp ~/.mitmproxy/mitmproxy-ca-cert.pem /usr/local/share/ca-certificates/mitmproxy-ca.crt
sudo update-ca-certificates
```

**Windows:**

```
certutil -addstore -user ROOT ~/.mitmproxy/mitmproxy-ca-cert.cer
```

### Port 5000 already in use

**Linux:**

```
kill $(lsof -t -i:5000)
```

**Windows:**

```
netstat -ano | findstr :5000
taskkill /PID <PID> /F
```

Alternatively, launch the Web UI on a different port:

```
python web_app.py --port 8080
```

---

*APISec v2.0 — ENSAT Tanger / DATAPROTECT Casablanca — 2026*