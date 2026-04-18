# APISec — Project Context

## Project
Automated API security audit tool — PFE + pre-employment stage.
Language: Python | CLI tool installed via `pip install -e .`

## Architecture
api_audit_tool/
├── main.py                  # CLI — apisec command
├── setup.py
├── core/
│   ├── discovery.py         # API detection + endpoint crawling
│   ├── rest_scanner.py      # REST vulnerability scanner
│   ├── graphql_scanner.py   # GraphQL scanner
│   ├── soap_scanner.py      # SOAP scanner
│   ├── param_discoverer.py  # Arjun-clone parameter discovery
│   └── requester.py         # HTTP layer
├── config/settings.py
├── logger/logger.py
└── wordlists/
## CLI Commands
```bash
apisec discovery --url URL --wordlist FILE --mode quick|full
apisec params    --input endpoints.json [--wordlist FILE]
apisec scan      --input endpoints.json --tests all [--token TOKEN]
apisec scan      --login-url /auth/login --username X --password Y --tests auth
apisec full      --url URL --wordlist FILE --tests all
```

## ScanResult fields (14 fields)
vuln_id, vuln_type, owasp, cwe, severity, confidence,
endpoint, method, parameter, payload, evidence,
description, solution, reference

## _TEST_REGISTRY (rest_scanner.py)
"misconfig" → _test_misconfig()   ✅ Done
"auth"      → _test_auth()        ✅ Done
"sqli"      → _test_sqli()        ❌ Next
"blind_sqli"→ _test_blind_sqli()  ❌ Next
"nosql"     → _test_nosql()       ❌ Planned
"xss"       → _test_xss()         ❌ Planned
"ssrf"      → _test_ssrf()        ❌ Planned
"idor"      → _test_idor()        ❌ Planned
"mass_assign"→_test_mass_assign() ❌ Planned
"rate_limit"→ _test_rate_limit()  ❌ Planned

## Misconfig checks (API8)
CORS-001 Reflected Origin         ✅
CORS-002 Wildcard + Credentials   ✅
CORS-003 Wildcard Origin          ✅
HDR-001  Missing HSTS             ✅ (skipped on HTTP)
HDR-002  Missing X-Content-Type   ✅
HDR-003  Missing X-Frame-Options  ✅
HDR-004  Missing CSP              ✅
INFO-001 Server version           ✅
INFO-002 X-Powered-By             ✅
VERB-001 HTTP TRACE               ✅
ERR-001  Verbose errors           ✅

## Auth checks (API2)
AUTH-001 No token required        ✅
AUTH-002 Invalid token accepted   ✅
AUTH-003 JWT none algorithm       ✅
AUTH-004 JWT alg confusion        ✅
AUTH-005 Rate limiting on login   ❌ Next

## Deduplication
Global checks (CORS, HDR, INFO, VERB) → deduplicated by vuln_id
Endpoint-specific (AUTH, SQLi...) → kept as-is

## Test targets
- JSONPlaceholder : https://jsonplaceholder.typicode.com
- Juice Shop      : http://localhost:3000
- crAPI           : http://localhost:8888

## Planning
Week 1-3  : Discovery + basics        ✅
Week 4    : JWT analyzer               partial
Week 5    : Exploit engine (SQLi...)   🔄 current
Week 6    : Analyzer + Score /100      ❌
Week 7    : Report PDF/HTML/JSON       ❌
Week 8    : Web dashboard              ❌
Week 9    : CLI integration + tests    ❌
Week 10   : Report writing + demo      ❌

## Next step
on continue avec l'implementation de _test_auth