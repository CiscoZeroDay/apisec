CONTEXT — APISec PFE Project
Je travaille sur APISec, un outil d'audit de sécurité API en Python (PFE). Voici l'état exact du projet :
Structure :
api_audit_tool/
├── main.py                    # CLI — commandes: discovery, params, scan, full, capture
├── core/
│   ├── discovery.py           # Détection API type + crawl endpoints
│   ├── rest_scanner.py        # Scanner REST — orchestration uniquement
│   ├── graphql_scanner.py
│   ├── soap_scanner.py
│   ├── param_discoverer.py
│   ├── models.py              # ScanResult dataclass
│   ├── vuln_db.py             # VulnDB singleton — data/rest_vulns.json
│   └── requester.py
├── exploit/
│   ├── sqli_engine.py         # SQLi via sqlmap
│   ├── mass_engine.py         # Mass Assignment (API3)
│   └── inventory_engine.py   # API9 — docs exposées, fichiers sensibles, debug, versioning
├── data/
│   └── rest_vulns.json        # KB avec: CORS-001/002/003, HDR-001/002/003/004, INFO-001/002, VERB-001, ERR-001, AUTH-001/002/003/004/005, SQLI-001, MASS-001, INV-001/002/003/004
└── wordlists/
    ├── api-endpoints-res.txt
    ├── swagger.txt             # SecLists
    ├── raft-large-files.txt    # SecLists
    └── raft-large-directories.txt # SecLists
Tests implémentés dans _TEST_REGISTRY :
python"misconfig":   ✅ CORS, Headers, TRACE, Errors
"auth":        ✅ AUTH-001 à AUTH-005 (JWT none, alg confusion, rate limit)
"sqli":        ✅ via sqlmap
"mass_assign": ✅ exploit/mass_engine.py
"inventory":   ✅ exploit/inventory_engine.py (API9)
# "nosql":     ❌ à implémenter
# "xss":       ❌ à implémenter
# "ssrf":      ❌ à implémenter
# "sensitive": ❌ à implémenter
# "idor":      ❌ à implémenter
Architecture — règle absolue :

rest_scanner.py = orchestration uniquement (stubs qui délèguent)
Logique complexe = fichier séparé dans exploit/
Pattern : _test_xxx(endpoint) → from exploit.xxx_engine import XxxEngine → engine.scan(endpoint)

CLI — arguments importants :
bashapisec scan --input endpoints.json --tests inventory
apisec scan --url https://xxx.net --endpoint /api/user/wiener --api-type REST --cookie "session=abc" --tests sqli
apisec discovery --url https://xxx.net --wordlist wordlists/api-endpoints-res.txt
Règles importantes :

Ne jamais réduire le code existant sans permission explicite
Toujours donner le code complet quand demandé
Code solide, professionnel, digne de PFE
Pas de hardcoding — sources dynamiques toujours préférées
Même pattern que sqli_engine.py pour tout nouveau moteur

Ce qu'on vient de finir :

inventory_engine.py avec threading (ThreadPoolExecutor) + HEAD-before-GET optimization
Bug trouvé : /.env n'est pas dans raft-large-files.txt → fix à faire : ajouter _ALWAYS_SENSITIVE paths au début de _check_sensitive_files() indépendamment de la wordlist

Prochaines implémentations (dans l'ordre) :

Fix inventory_engine.py — _ALWAYS_SENSITIVE toujours testés
sensitive_data — détecter données sensibles dans réponses API (passwords, API keys, tokens, PII)
xss — Reflected XSS dans réponses JSON
ssrf — URL injection + AWS metadata
nosql — MongoDB operator injection

Repo GitHub : https://github.com/CiscoZeroDay/apisec.git