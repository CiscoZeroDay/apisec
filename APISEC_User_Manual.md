# APISec — User Manual

**Version:** 2.0  
**Author:** RAZAFINDRAIBE Hery Jhonny  
**Institution:** ENSAT Tanger / DATAPROTECT Casablanca  
**Repository:** https://github.com/CiscoZeroDay/apisec

---

## Table of Contents

1. Overview
2. General Usage
3. Global Options
4. Commands
   - 4.1 discovery
   - 4.2 params
   - 4.3 scan
   - 4.4 full
   - 4.5 capture
   - 4.6 exploit
   - 4.7 schema
   - 4.8 report
5. Authentication Options
6. Available Tests
7. Typical Workflows
8. Web Interface
9. Output Files Reference

---

## 1. Overview

APISec is a command-line API security auditing tool supporting REST, GraphQL, and SOAP protocols. It provides automated discovery, vulnerability scanning, traffic capture, exploitation, and PDF report generation within a unified platform.

The general invocation syntax is:

```
apisec <command> [options]
```

---

## 2. General Usage

```
apisec --help
apisec <command> --help
```

All commands share a common set of global options described in Section 3. Each command also accepts its own specific arguments described in Section 4.

---

## 3. Global Options

The following options are available across all commands.

| Option | Type | Default | Description |
|---|---|---|---|
| `--timeout` | int | 5 | HTTP request timeout in seconds (1–60) |
| `--token` | string | None | Bearer token for authenticated scans |
| `--token-file` | path | None | Path to a file containing the Bearer token |
| `--login-url` | string | None | Login endpoint for auto-authentication |
| `--username` | string | None | Username or email for auto-login |
| `--password` | string | None | Password for auto-login |
| `--login-body` | string | None | Raw JSON body for custom login requests |
| `--cookie` | string | None | Cookie string for injection tests (e.g. `session=abc; csrf=xyz`) |
| `--api-key` | string | None | API key value for injection tests |
| `--api-key-name` | string | X-API-Key | API key header name |
| `--second-token` | string | None | Second account JWT for IDOR confirmation |
| `--output` | path | None | Output file path for JSON results |
| `--json` | flag | false | Print raw JSON output to stdout |
| `--verbose` | flag | false | Enable verbose logging |
| `--deep` | flag | false | Enable time-based techniques (slower but more thorough) |

---

## 4. Commands

### 4.1 discovery

Detects the API type, crawls available endpoints, and extracts the GraphQL schema when applicable. This command must be run first before any scan.

**Syntax:**

```
apisec discovery --url URL --wordlist FILE [--mode quick|full] [options]
```

**Arguments:**

| Argument | Required | Default | Description |
|---|---|---|---|
| `--url` | Yes | — | Target API base URL (must start with http:// or https://) |
| `--wordlist` | Yes | — | Path to the endpoint wordlist file |
| `--mode` | No | quick | Crawl mode: `quick` (first 50 paths) or `full` (entire wordlist) |

**Output:**

The command saves discovery results to `endpoints.json` by default (overridable with `--output`). The file contains the detected API type, confidence score, list of endpoints, and the GraphQL schema if applicable.

**Examples:**

```
apisec discovery --url https://api.example.com --wordlist wordlists/api-endpoints-res.txt

apisec discovery --url https://api.example.com --wordlist wordlists/api-endpoints-res.txt --mode full

apisec discovery --url https://api.example.com --wordlist wordlists/api-endpoints-res.txt --output results/endpoints.json --verbose
```

---

### 4.2 params

Discovers undocumented HTTP parameters accepted by each REST endpoint. This command is specific to REST APIs. For GraphQL and SOAP, parameter discovery is not required as arguments are derived from the schema or WSDL respectively.

**Syntax:**

```
apisec params --input FILE [--wordlist FILE] [options]
```

**Arguments:**

| Argument | Required | Default | Description |
|---|---|---|---|
| `--input` | Yes | — | Path to `endpoints.json` produced by `apisec discovery` |
| `--wordlist` | No | None | Custom parameters wordlist (uses built-in wordlist if omitted) |

**Output:**

Results are saved to `params.json` by default (overridable with `--output`).

**Examples:**

```
apisec params --input endpoints.json

apisec params --input endpoints.json --wordlist wordlists/params.txt --token eyJhbGci...
```

---

### 4.3 scan

Tests discovered endpoints for security vulnerabilities. Accepts either a discovery output file or a single endpoint specified directly on the command line.

**Syntax:**

```
apisec scan --input FILE [--tests all] [options]
apisec scan --url URL --endpoint PATH [--tests all] [--api-type REST|GraphQL|SOAP] [options]
apisec scan --input FILE --list-tests
```

**Arguments:**

| Argument | Required | Default | Description |
|---|---|---|---|
| `--input` | Conditional | None | Path to `endpoints.json` from discovery |
| `--url` | Conditional | None | Base URL (required when using `--endpoint`) |
| `--endpoint` | Conditional | None | Single path to test (e.g. `/users/1`) |
| `--tests` | No | all | Tests to run: `all`, comma-separated names, or numbers (e.g. `1,3,4`) |
| `--list-tests` | No | false | List available tests for the detected API type and exit |
| `--api-type` | No | REST | Force API type when using `--endpoint` directly |

**Specifying tests:**

```
--tests all                  Run all implemented tests
--tests 0                    Equivalent to all
--tests sqli,idor,auth       Run specific named tests
--tests 1,3,4                Run tests by number (see --list-tests)
```

**Output:**

Results are printed to the terminal and saved to a JSON file when `--output` is specified.

**Examples:**

```
apisec scan --input endpoints.json --tests all

apisec scan --input endpoints.json --tests sqli,idor --token eyJhbGci...

apisec scan --url http://localhost:8000 --endpoint /api/users/1 --tests idor --api-type REST

apisec scan --input endpoints.json --list-tests

apisec scan --input endpoints.json --tests all --output scan_results.json --verbose
```

---

### 4.4 full

Chains the discovery and scan phases into a single command. Equivalent to running `apisec discovery` followed by `apisec scan`.

**Syntax:**

```
apisec full --url URL --wordlist FILE [--tests all] [options]
```

**Arguments:**

| Argument | Required | Default | Description |
|---|---|---|---|
| `--url` | Yes | — | Target API base URL |
| `--wordlist` | Yes | — | Path to the endpoint wordlist file |
| `--mode` | No | quick | Crawl mode: `quick` or `full` |
| `--tests` | No | all | Tests to run (same syntax as `apisec scan`) |
| `--scan-output` | No | scan_results.json | Output file for scan results |

**Examples:**

```
apisec full --url https://api.example.com --wordlist wordlists/api-endpoints-res.txt --tests all

apisec full --url https://api.example.com --wordlist wordlists/api-endpoints-res.txt --mode full --tests sqli,auth --token eyJhbGci... --output endpoints.json --scan-output results.json
```

---

### 4.5 capture

Captures live HTTP/HTTPS traffic via a transparent mitmproxy-based proxy, or reads and analyzes an existing `.mitm` traffic file.

**Syntax:**

```
apisec capture --url URL [--port 8080] [options]
apisec capture --url URL --read FILE [--full-requests] [--filter TYPE] [options]
```

**Arguments:**

| Argument | Required | Default | Description |
|---|---|---|---|
| `--url` | Yes | — | Target API base URL |
| `--port` | No | 8080 | Proxy port for live capture |
| `--read` | No | None | Path to an existing `.mitm` file to analyze instead of live capture |
| `--full-requests` | No | false | Display complete request and response details after the summary |
| `--filter` | No | None | Filter requests by type: `graphql`, `mutations`, `queries`, `rest`, `soap` |
| `--requests-output` | No | requests.json | Output file for request details |
| `--traffic-file` | No | traffic.mitm | Output file for raw mitmproxy flows |
| `--swagger-file` | No | swagger_captured.yaml | Intermediate OpenAPI specification file |

**Examples:**

```
apisec capture --url https://api.example.com --port 8080

apisec capture --url https://api.example.com --read traffic.mitm

apisec capture --url https://api.example.com --read traffic.mitm --full-requests

apisec capture --url https://api.example.com --read traffic.mitm --filter graphql

apisec capture --url https://api.example.com --read traffic.mitm --filter mutations --full-requests
```

---

### 4.6 exploit

Runs post-detection exploitation modules against confirmed GraphQL vulnerabilities. This command is currently limited to GraphQL APIs.

**Syntax:**

```
apisec exploit --input FILE [--scan-input FILE] [--exploits E1,E2] [options]
```

**Arguments:**

| Argument | Required | Default | Description |
|---|---|---|---|
| `--input` | Yes | — | Path to `endpoints.json` from discovery |
| `--scan-input` | No | None | Path to `scan_results.json` from a previous scan (optional) |
| `--exploits` | No | all | Exploits to run: `E1,E2,E3` or `all` |
| `--output-dir` | No | . | Directory for generated proof-of-concept files |

**Available exploit modules:**

| ID | Triggered by | Description |
|---|---|---|
| E1 | GQL-S1 | Full schema cartography after confirmed introspection |
| E2 | GQL-S3 | Extraction of actual values from detected sensitive fields |
| E3 | GQL-S5 | Enumeration of object IDs across all schema queries |
| E4 | GQL-S10 | Credential bruteforce via GraphQL alias batching |

**Examples:**

```
apisec exploit --input endpoints.json

apisec exploit --input endpoints.json --scan-input scan_results.json

apisec exploit --input endpoints.json --exploits E1,E3 --output-dir ./poc
```

---

### 4.7 schema

Exports the GraphQL schema from a discovery result file into formats compatible with visual schema exploration tools.

**Syntax:**

```
apisec schema --input FILE [--format voyager|sdl|both] [--output-dir DIR] [options]
```

**Arguments:**

| Argument | Required | Default | Description |
|---|---|---|---|
| `--input` | Yes | — | Path to `endpoints.json` from a GraphQL discovery |
| `--format` | No | both | Export format: `voyager` (introspection JSON), `sdl`, or `both` |
| `--output-dir` | No | . | Directory for output files |

**Compatible visualization tools:**

| Format | Tool | URL |
|---|---|---|
| voyager | GraphQL Voyager | https://graphql-kit.com/graphql-voyager/ |
| sdl | GraphQL Voyager (SDL tab) | https://graphql-kit.com/graphql-voyager/ |
| sdl | Nathan Randal Visualizer | https://nathanrandal.com/graphql-visualizer/ |

**Examples:**

```
apisec schema --input endpoints.json

apisec schema --input endpoints.json --format sdl --output-dir ./schema
```

---

### 4.8 report

Generates a structured PDF security report from scan results. The report follows a professional penetration testing report format including an executive summary, OWASP API Top 10 coverage matrix, detailed findings with evidence, and a priority remediation plan.

**Syntax:**

```
apisec report --input FILE [--discovery FILE] [--output FILE] [options]
```

**Arguments:**

| Argument | Required | Default | Description |
|---|---|---|---|
| `--input` | Yes | — | Path to `scan_results.json` from `apisec scan` |
| `--discovery` | No | None | Path to `endpoints.json` for target URL and API type context |
| `--output` | No | apisec_report.pdf | Output PDF file path |

**Examples:**

```
apisec report --input scan_results.json

apisec report --input scan_results.json --discovery endpoints.json

apisec report --input scan_results.json --discovery endpoints.json --output reports/audit_report.pdf
```

---

## 5. Authentication Options

APISec supports multiple authentication mechanisms for scanning authenticated endpoints.

### Bearer Token

```
apisec scan --input endpoints.json --token eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...
```

### Token from File

```
apisec scan --input endpoints.json --token-file /path/to/token.txt
```

### Auto-Login

```
apisec scan --input endpoints.json --login-url https://api.example.com/auth/login --username admin@example.com --password secret
```

### Cookie

```
apisec scan --input endpoints.json --cookie "session=abc123; csrf=xyz456"
```

### API Key

```
apisec scan --input endpoints.json --api-key sk-live-abc123 --api-key-name X-API-Key
```

### IDOR Confirmation (Second Account)

```
apisec scan --input endpoints.json --token eyJhbGci... --second-token eyJhbGci...
```

---

## 6. Available Tests

### REST Tests

| Name | OWASP Category | Description |
|---|---|---|
| misconfig | API8:2023 | CORS, missing security headers, server version disclosure, HTTP TRACE |
| auth | API2:2023 | Broken authentication and token validation |
| sqli | API8:2023 | SQL injection detection via sqlmap integration |
| blind_sqli | API8:2023 | Blind SQL injection (time-based) |
| nosql | API8:2023 | NoSQL injection via boolean and operator techniques |
| xss | API8:2023 | Cross-site scripting in API responses |
| idor | API1:2023 | Insecure direct object reference via ID enumeration |
| ssrf | API7:2023 | Server-side request forgery |
| bflaw | API5:2023 | Broken function level authorization |
| mass_assign | API3:2023 | Mass assignment via hidden field injection |
| rate_limit | API4:2023 | Rate limiting absence and bypass |
| inventory | API9:2023 | Exposed documentation, debug endpoints, deprecated versions |
| sensitive | API3:2023 | Sensitive data exposure in API responses |

### GraphQL Tests

| Name | OWASP Category | Description |
|---|---|---|
| introspection | API8:2023 | Introspection exposure and bypass techniques |
| bypass | API8:2023 | Introspection bypass via newline injection and GET method |
| fields | API3:2023 | Sensitive field exposure in schema |
| auth | API2:2023 | Broken authentication on queries and mutations |
| idor | API1:2023 | IDOR via GraphQL ID arguments |
| csrf | API8:2023 | CSRF via HTTP GET requests |
| sqli | API8:2023 | SQL injection in GraphQL arguments |
| nosqli | API8:2023 | NoSQL injection in GraphQL arguments |
| batch | API4:2023 | Query batching abuse |
| alias | API4:2023 | Alias-based rate limit bypass |
| depth | API4:2023 | Excessive query depth |
| subscription | API8:2023 | Subscription endpoint exposure |
| error | API8:2023 | Verbose error messages leaking schema information |

### SOAP Tests

| Name | OWASP Category | Description |
|---|---|---|
| wsdl | API8:2023 | WSDL exposure and enumeration |
| xxe | API8:2023 | XML External Entity injection |
| sqli | API8:2023 | SQL injection in SOAP parameters |
| injection | API8:2023 | XML and SOAP parameter injection |
| auth | API2:2023 | WS-Security authentication bypass |
| replay | API2:2023 | SOAP replay attack via identical request and expired timestamp |
| action_spoofing | API8:2023 | SOAPAction header spoofing |

---

## 7. Typical Workflows

### Black-box REST Audit

```
apisec discovery --url https://api.example.com --wordlist wordlists/api-endpoints-res.txt --mode full
apisec params    --input endpoints.json
apisec scan      --input endpoints.json --tests all --output scan_results.json
apisec report    --input scan_results.json --discovery endpoints.json --output report.pdf
```

### Gray-box REST Audit (Known Endpoints)

```
apisec scan --input endpoints.json --tests all --token eyJhbGci... --output scan_results.json
apisec report --input scan_results.json --discovery endpoints.json
```

### Black-box GraphQL Audit

```
apisec discovery --url https://api.example.com --wordlist wordlists/api-endpoints-res.txt
apisec scan      --input endpoints.json --tests all --output scan_results.json
apisec exploit   --input endpoints.json --scan-input scan_results.json
apisec schema    --input endpoints.json --format both
apisec report    --input scan_results.json --discovery endpoints.json
```

### SOAP Audit

```
apisec discovery --url http://localhost:7777 --wordlist wordlists/api-endpoints-res.txt
apisec scan      --input endpoints.json --tests all --output scan_results.json
apisec report    --input scan_results.json --discovery endpoints.json
```

### Full Automated Scan (Single Command)

```
apisec full --url https://api.example.com --wordlist wordlists/api-endpoints-res.txt --tests all --mode full --scan-output scan_results.json
```

### Traffic Capture Workflow

```
# Step 1 — Start the proxy and browse the target application
apisec capture --url https://api.example.com --port 8080

# Step 2 — Configure your browser proxy settings to 127.0.0.1:8080
# Step 3 — Navigate the application normally, then stop the capture (Ctrl+C)

# Step 4 — Analyze the captured traffic
apisec capture --url https://api.example.com --read traffic.mitm --full-requests --filter graphql

# Step 5 — Scan the captured endpoints
apisec scan --input endpoints.json --tests all
```

---

## 8. Web Interface

APISec provides a web-based interface as an alternative to the CLI, designed for users who prefer a graphical environment for configuring and monitoring scans.

### Starting the Web Interface

```
python web_app.py
```

Open a browser and navigate to: **http://localhost:5000**

To use a different port:

```
python web_app.py --port 8080
```

### Available Features

| Feature | Description |
|---|---|
| Scan configuration | Set target URL, API type, specific endpoint, discovery mode, and timeout |
| Authentication | Configure Bearer token, second token, cookie, API key, and auto-login credentials |
| Test selection | Select all tests or individual tests per protocol |
| Real-time monitoring | Live scan logs streamed to the browser via Server-Sent Events (SSE) |
| Findings dashboard | Color-coded findings grouped by severity (CRITICAL, HIGH, MEDIUM, LOW, INFO) |
| PDF report download | Generate and download the security report directly from the browser |
| JSON export | Download raw scan results in JSON format |
| AI assistant | Analyze findings and get remediation suggestions powered by Groq or Ollama |

### CLI vs Web Interface Comparison

| Capability | CLI | Web Interface |
|---|---|---|
| API discovery | `apisec discovery` | Integrated in scan configuration |
| Vulnerability scan | `apisec scan` | Graphical scan form |
| Real-time logs | Terminal output | SSE streaming in browser |
| PDF report | `apisec report` | Download button |
| JSON export | `--output FILE` | Download button |
| AI assistant | Not available | Available |
| Parameter discovery | `apisec params` | Automatic before scan |
| Traffic capture | `apisec capture` | Not available |
| GraphQL exploit | `apisec exploit` | Not available |
| Schema export | `apisec schema` | Not available |

### Notes

- The web interface uses the same underlying scanning engine as the CLI. Results are identical regardless of the mode used.
- The AI assistant requires a configured Groq API key or a running Ollama instance. Refer to Section 5 of the Installation Guide for configuration instructions.
- The web interface does not persist scan history between sessions. Results are available for download immediately after the scan completes.

---

## 9. Output Files Reference

| File | Produced by | Description |
|---|---|---|
| `endpoints.json` | `discovery`, `full`, `capture` | Detected API type, endpoints, GraphQL schema |
| `params.json` | `params` | Discovered parameters per endpoint |
| `scan_results.json` | `scan`, `full` | List of detected vulnerabilities with evidence |
| `requests.json` | `capture` | Full details of captured HTTP requests |
| `traffic.mitm` | `capture` | Raw mitmproxy flow file |
| `swagger_captured.yaml` | `capture` | Intermediate OpenAPI specification |
| `apisec_report.pdf` | `report` | Professional PDF security report |

---
