# 📖 APISEC — User Manual

> **Version:** 2.0 | **Author:** RAZAFINDRAIBE Hery Jhonny | **ENSAT Tanger / DATAPROTECT Casablanca**

---

## 📋 Table of Contents

1. [Overview](#overview)
2. [Quick Start — Web UI (Beginner)](#quick-start--web-ui-beginner)
3. [Advanced Usage — CLI](#advanced-usage--cli)
4. [CLI Command Reference](#cli-command-reference)
5. [Understanding Scan Results](#understanding-scan-results)
6. [AI Assistant](#ai-assistant)
7. [Scan History and Reports](#scan-history-and-reports)
8. [Best Practices](#best-practices)

---

## 1. 🎯 Overview

APISEC is an automated API security auditing tool that supports three protocols :

| Protocol | Auto-detected | Security checks |
|---|---|---|
| 🟢 REST | ✅ Yes | 12 modules · 43 checks |
| 🟣 GraphQL | ✅ Yes | 10 modules · 17 checks |
| 🟠 SOAP | ✅ Yes | 7 modules · 12 checks |

**Two interfaces available :**
- 🖥️ **Web UI** — browser-based, for beginners and quick assessments
- ⌨️ **CLI** — command-line, for advanced users and pipeline integration

> ⚠️ **Legal disclaimer:** Only scan APIs you own or have explicit written authorization to test. Unauthorized scanning is illegal.

---

## 2. 🖥️ Quick Start — Web UI (Beginner)

### Step 1 — Start the Web UI

```bash
python web_app.py
```

Open your browser at : **http://localhost:5000**

---

### Step 2 — Configure your scan

Fill in the scan form :

| Field | Description | Example |
|---|---|---|
| **Target URL** | Base URL of the API to scan | `http://localhost:8888` |
| **API Type** | Leave as AUTO for automatic detection | `AUTO` |
| **Tests** | Select ALL or individual modules | `ALL` |
| **Auth Token** | JWT or API key (optional) | `eyJhbGci...` |

---

### Step 3 — Launch the scan

Click **▶ LAUNCH SCAN**

The console will show real-time scan progress :

```
▶  Target  : http://localhost:8888
▶  Mode    : AUTO DISCOVERY
▶  Tests   : all
──────────────────────────────────────────────────────────────
[→] Starting API discovery...
[✓] REST API detected (confidence: 87%)
[→] Discovered 12 endpoints
[→] Running misconfig tests...
[VULN] CORS-001 — Reflected Origin CORS Misconfiguration
[→] Running auth tests...
[VULN] AUTH-003 — JWT none Algorithm Accepted
✅  Scan done — 5 finding(s) in 42.3s
```

---

### Step 4 — Review findings

After the scan, findings appear as cards below the console :

Each card shows :
- 🔴 **Severity** — CRITICAL / HIGH / MEDIUM / LOW / INFO
- **Vulnerability name** and OWASP mapping
- **Affected endpoint** and HTTP method
- **Payload used** to detect the vulnerability
- **Evidence** — what changed in the response
- **Remediation guidance**

---

### Step 5 — Download the report

Click **📄 Download PDF** or **📋 Download JSON** to export the full report.

---

## 3. ⌨️ Advanced Usage — CLI

The CLI provides full control over the scan pipeline and is suitable for integration into automated security workflows.

### Full pipeline (recommended)

```bash
# Step 1: Discover endpoints
python main.py discovery --url https://api.example.com \
    --wordlist wordlists/swagger.txt

# Step 2: Discover parameters (REST only)
python main.py params --input endpoints.json

# Step 3: Run security scan
python main.py scan --input endpoints.json --tests all

# OR: Run everything in one command
python main.py full --url https://api.example.com \
    --wordlist wordlists/swagger.txt --tests all
```

---

### Authenticated scan

```bash
# Bearer token
python main.py full --url https://api.example.com \
    --token eyJhbGciOiJSUzI1NiJ9... \
    --tests all

# Login credentials (auto-login)
python main.py full --url https://api.example.com \
    --login-url https://api.example.com/auth/login \
    --username admin@example.com \
    --password secret123 \
    --tests all

# Two tokens for IDOR confirmation
python main.py scan --input endpoints.json \
    --token eyJ_user1... \
    --second-token eyJ_user2... \
    --tests idor
```

---

### Targeted single endpoint scan

```bash
# Test only one endpoint with specific tests
python main.py scan \
    --url https://api.example.com \
    --endpoint /api/users/1 \
    --tests sqli,nosql,idor \
    --token eyJhbGci...
```

---

### GraphQL scan

```bash
# Auto-detected
python main.py full --url https://api.example.com/graphql \
    --tests all

# Schema extraction only
python main.py schema --input endpoints.json --format both

# With introspection bypass
python main.py scan --input endpoints.json \
    --api-type graphql --tests bypass,auth,depth
```

---

### SOAP scan

```bash
python main.py full --url https://service.example.com/api \
    --wordlist wordlists/swagger.txt \
    --tests wsdl,xxe,sqli,auth
```

---

### Traffic capture (when wordlist fails)

```bash
# Start capture proxy
python main.py capture --url https://api.example.com --port 8080

# Configure browser proxy: localhost:8080
# Browse the application normally
# Press ENTER when done

# Read existing capture file
python main.py capture --url https://api.example.com \
    --read traffic.mitm

# Full request details
python main.py capture --url https://api.example.com \
    --read traffic.mitm --full-requests
```

---

### List available tests

```bash
# List all REST tests
python main.py scan --url http://x --tests all --list-tests

# Run test by number
python main.py scan --input endpoints.json --tests 0
python main.py scan --input endpoints.json --tests 1,3,5
```

---

## 4. 📚 CLI Command Reference

### Global options (available on all commands)

| Option | Description | Default |
|---|---|---|
| `--timeout` | HTTP request timeout in seconds | `5` |
| `--token` | Bearer token for authentication | None |
| `--token-file` | Path to file containing the token | None |
| `--login-url` | Auto-login endpoint URL | None |
| `--username` | Login username | None |
| `--password` | Login password | None |
| `--login-body` | Raw JSON login body | None |
| `--cookie` | Session cookie string | None |
| `--api-key` | API key value | None |
| `--api-key-name` | API key header name | `X-API-Key` |
| `--second-token` | Second account token for IDOR | None |
| `--output` | Output file path | Auto-generated |
| `--json` | Output results as JSON | False |
| `--verbose` | Verbose logging | False |
| `--deep` | Deep scan mode (slower, more thorough) | False |

---

### `discovery` — API detection and endpoint crawl

```bash
python main.py discovery --url URL --wordlist FILE [--mode quick|full]
```

| Option | Description |
|---|---|
| `--url` | Target URL (required) |
| `--wordlist` | Endpoint wordlist path (required) |
| `--mode` | `quick` (fast) or `full` (recursive depth crawl) |

**Output:** `endpoints.json` — API type, confidence, and discovered endpoints

---

### `params` — Parameter discovery (REST only)

```bash
python main.py params --input endpoints.json [--wordlist FILE]
```

| Option | Description |
|---|---|
| `--input` | endpoints.json from discovery (required) |
| `--wordlist` | Custom parameter wordlist |

**Output:** Updated `endpoints.json` with discovered parameters

---

### `scan` — Vulnerability scan

```bash
python main.py scan --input endpoints.json [--tests all]
python main.py scan --url URL --endpoint /path [--tests sqli,idor]
```

| Option | Description |
|---|---|
| `--input` | endpoints.json (or use --url + --endpoint) |
| `--url` | Base URL (with --endpoint) |
| `--endpoint` | Single path to test |
| `--tests` | `all`, test names (e.g. `sqli,nosql`), or test numbers |
| `--api-type` | Force protocol: `REST`, `GraphQL`, `SOAP` |
| `--list-tests` | Print available tests and exit |

---

### `full` — Full pipeline (discovery + params + scan)

```bash
python main.py full --url URL --wordlist FILE [--tests all]
```

Runs discovery → params → scan in sequence.

---

### `schema` — GraphQL schema extraction

```bash
python main.py schema --input endpoints.json [--format json|sdl|both]
```

| Option | Description |
|---|---|
| `--input` | endpoints.json with GraphQL endpoint |
| `--format` | Output format: `json`, `sdl`, or `both` |
| `--output-dir` | Directory for schema files |

---

### `capture` — Traffic capture via mitmproxy

```bash
python main.py capture --url URL [--port 8080]
python main.py capture --url URL --read traffic.mitm [--full-requests]
```

| Option | Description |
|---|---|
| `--url` | Target API URL |
| `--port` | Proxy port (default: 8080) |
| `--read` | Read existing .mitm file instead of capturing |
| `--full-requests` | Show full request/response details |
| `--filter` | Filter by type: `graphql`, `soap`, `rest` |

---

## 5. 📊 Understanding Scan Results

### Severity levels

| Severity | Color | Meaning |
|---|---|---|
| 🔴 CRITICAL | Red | Immediate exploitation risk — fix now |
| 🟠 HIGH | Orange | Significant risk — fix as soon as possible |
| 🟡 MEDIUM | Yellow | Moderate risk — plan remediation |
| 🟢 LOW | Green | Low risk — monitor and review |
| ⚪ INFO | Gray | Informational — no immediate action needed |

### Confidence levels

| Confidence | Meaning |
|---|---|
| HIGH | Direct evidence — the response proves the vulnerability |
| MEDIUM | Indirect evidence — behavioral deviation detected, manual confirmation recommended |
| LOW | Pattern match — manual verification required |

### Finding fields

Each finding contains :

| Field | Description |
|---|---|
| `vuln_id` | Unique identifier (e.g. CORS-001, GQL-S4) |
| `vuln_type` | Vulnerability category |
| `severity` | CRITICAL / HIGH / MEDIUM / LOW / INFO |
| `confidence` | HIGH / MEDIUM / LOW |
| `owasp` | OWASP API Security Top 10 mapping |
| `cwe` | CWE identifier |
| `endpoint` | Affected URL |
| `method` | HTTP method used |
| `parameter` | Affected parameter |
| `payload` | Exact payload that triggered the finding |
| `evidence` | What changed in the response — proof of vulnerability |
| `description` | Technical explanation |
| `solution` | Remediation guidance |
| `reference` | External reference URL |

---

## 6. 🤖 AI Assistant

The AI assistant helps interpret findings and suggest remediation strategies.

### Setup via Web UI

1. Click the **AI** icon in the top bar
2. Select provider : **Groq** (free) or **Ollama** (local)
3. Enter your API key (Groq) or confirm Ollama is running
4. Click **Save**

### Setup via environment variables

```bash
# Groq (free)
export APISEC_AI_PROVIDER=groq
export GROQ_API_KEY=gsk_your_key

# Ollama (local)
export APISEC_AI_PROVIDER=ollama
export OLLAMA_MODEL=llama3.2
ollama serve  # must be running
```

### Using the AI assistant

After a scan completes :
1. Click **🤖 Analyze with AI** on any finding card
2. The AI will explain the vulnerability, the attack scenario, and suggest fixes
3. Use the **chat** tab for free-form security questions

> ⚠️ **Privacy note:** When using Groq, scan findings are sent to Groq's API. Use Ollama for sensitive targets requiring data confidentiality.

---

## 7. 📁 Scan History and Reports

### Web UI — History page

Navigate to **http://localhost:5000/history** to see :
- All past scans with date, target, API type, and finding counts
- KPI dashboard — total scans, findings by severity
- Export options per scan

### Report formats

| Format | How to get it | Contents |
|---|---|---|
| PDF | Click **Download PDF** in Web UI or history | Full report with findings, evidence, remediation |
| JSON | Click **Download JSON** or use `/api/report/<id>/json` | Machine-readable findings for further processing |

### CLI — Access scan history

```bash
# List all scans (via Flask API)
curl http://localhost:5000/api/scans

# Get specific scan
curl http://localhost:5000/api/scans/<scan_id>

# Download JSON report
curl http://localhost:5000/api/report/<scan_id>/json > report.json

# Download PDF report
curl http://localhost:5000/api/report/<scan_id>/pdf > report.pdf
```

---

## 8. 💡 Best Practices

### For beginners

- ✅ Start with the **Web UI** for the first scan
- ✅ Always scan in a **controlled test environment** first
- ✅ Use **AUTO** API type detection — let APISEC identify the protocol
- ✅ Review each finding manually before reporting it

### For advanced users

- ✅ Use `--second-token` for IDOR tests to get HIGH confidence results
- ✅ Use `--deep` mode for thorough SQL injection testing
- ✅ Combine `discovery` → `params` → `scan` separately for better control
- ✅ Use `capture` mode when the API requires authentication to reveal endpoints
- ✅ Save `endpoints.json` and reuse it for multiple targeted scans

### For CI/CD integration

```bash
# Non-interactive scan with JSON output
python main.py full \
    --url https://staging-api.example.com \
    --wordlist wordlists/swagger.txt \
    --tests all \
    --token $API_TOKEN \
    --json \
    --output results.json

# Exit code: 0 = no findings, 1 = findings detected
echo "Exit code: $?"
```

### Scan scope recommendations

| Scenario | Recommended command |
|---|---|
| Quick security check | `full --tests misconfig,auth` |
| Full REST audit | `full --tests all --deep` |
| GraphQL audit | `full --api-type graphql --tests all` |
| SOAP audit | `full --api-type soap --tests wsdl,xxe,sqli,auth` |
| Single endpoint deep test | `scan --endpoint /api/users/1 --tests sqli,nosql,idor` |
| Unknown API exploration | `discovery --mode full` then review endpoints.json |

---

*User Manual — APISEC v2.0 | ENSAT Tanger / DATAPROTECT Casablanca 2026*
