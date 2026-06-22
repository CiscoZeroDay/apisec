# core/report_generator.py
"""
APISec Report Generator — LaTeX-style PDF via pdflatex.

Usage (CLI):
    apisec report --input scan_results.json --output report.pdf
    apisec report --input scan_results.json --discovery endpoints.json --output report.pdf

Architecture:
    1. Load scan_results.json  (list of ScanResult dicts)
    2. Load endpoints.json     (optional — for target URL, api_type, schema info)
    3. Render a .tex template  (in-memory string, no template files needed)
    4. Compile with pdflatex   (subprocess, two passes for TOC)
    5. Clean up .tex/.aux/.log
"""

from __future__ import annotations

import json
import os
import re
import subprocess
import tempfile
from datetime import datetime
from typing import Optional


# ─────────────────────────────────────────────────────────────────────────────
#  Severity config
# ─────────────────────────────────────────────────────────────────────────────

_SEV_COLOR = {
    "CRITICAL": "BF0000",
    "HIGH":     "D95F00",
    "MEDIUM":   "D4A017",
    "LOW":      "2E7D32",
    "INFO":     "1565C0",
}

_SEV_ORDER = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]


# ─────────────────────────────────────────────────────────────────────────────
#  LaTeX escaping
# ─────────────────────────────────────────────────────────────────────────────

_SMART_CHAR_MAP = {
    "\u2018": "'",
    "\u2019": "'",
    "\u201c": '"',
    "\u201d": '"',
    "\u2013": "-",
    "\u2014": "--",
    "\u2026": "...",
    "\u00a0": " ",
}

_CONTROL_CHAR_RE = re.compile(
    r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f-\x9f]"
)


def _sanitize(text: str) -> str:
    """
    Normalize/strip characters that are valid in Python strings but invalid
    or unsafe for raw insertion into a LaTeX source file.

    Must run BEFORE any LaTeX escaping so that every text field is
    guaranteed clean before reaching pdflatex.

    Steps:
      1. Replace known smart punctuation with ASCII equivalents
      2. Drop Unicode replacement character and C0/C1 control chars
      3. Strip ALL remaining non-ASCII characters (e.g. U+2666 diamond,
         box-drawing chars, emoji) — keeps only printable ASCII 0x20-0x7E
         This prevents pdflatex "Invalid UTF-8 byte" errors from
         special characters in scan evidence/payloads.
    """
    if not text:
        return ""
    text = str(text)
    for bad, good in _SMART_CHAR_MAP.items():
        text = text.replace(bad, good)
    text = text.replace("\ufffd", "")
    text = _CONTROL_CHAR_RE.sub("", text)
    # Strip ALL non-ASCII — keeps only printable ASCII (0x20-0x7E)
    # Replaces any remaining Unicode symbol with a space
    text = "".join(c if 0x20 <= ord(c) <= 0x7E else " " for c in text)
    return text


def _esc(text: str) -> str:
    """Sanitize then escape special LaTeX characters in plain text."""
    if not text:
        return ""
    text = _sanitize(text)
    replacements = [
        ("\\", r"\textbackslash{}"),
        ("&",  r"\&"),
        ("%",  r"\%"),
        ("$",  r"\$"),
        ("#",  r"\#"),
        ("_",  r"\_"),
        ("{",  r"\{"),
        ("}",  r"\}"),
        ("~",  r"\textasciitilde{}"),
        ("^",  r"\textasciicircum{}"),
        ("<",  r"\textless{}"),
        (">",  r"\textgreater{}"),
    ]
    for char, escaped in replacements:
        text = text.replace(char, escaped)
    return text


def _esc_url(url: str) -> str:
    """Sanitize then escape URL for LaTeX — allow line breaks."""
    if not url:
        return ""
    url = _sanitize(url)
    escaped = url.replace("%", r"\%").replace("#", r"\#").replace("_", r"\_")
    escaped = escaped.replace("/", r"/\allowbreak{}").replace(".", r".\allowbreak{}")
    return escaped


def _verbatim(text: str) -> str:
    """Sanitize and wrap text in a LaTeX verbatim-safe box."""
    if not text:
        return r"\textit{N/A}"
    cleaned = _sanitize(text).replace("\n", " ").replace("\r", "")[:300]
    return r"\texttt{" + _esc(cleaned) + r"}"


# ─────────────────────────────────────────────────────────────────────────────
#  Data loading
# ─────────────────────────────────────────────────────────────────────────────

def _load_scan_results(path: str) -> list[dict]:
    with open(path, "r", encoding="utf-8", errors="replace") as f:
        data = json.load(f)
    if isinstance(data, list):
        return data
    return []


def _load_discovery(path: Optional[str]) -> dict:
    if not path or not os.path.isfile(path):
        return {}
    try:
        with open(path, "r", encoding="utf-8", errors="replace") as f:
            return json.load(f)
    except Exception:
        return {}


# ─────────────────────────────────────────────────────────────────────────────
#  Summary statistics
# ─────────────────────────────────────────────────────────────────────────────

def _compute_stats(findings: list[dict]) -> dict:
    counts = {s: 0 for s in _SEV_ORDER}
    for f in findings:
        sev = f.get("severity", "INFO").upper()
        if sev in counts:
            counts[sev] += 1
    total = sum(counts.values())

    risk = (
        counts["CRITICAL"] * 10
        + counts["HIGH"]     * 5
        + counts["MEDIUM"]   * 2
        + counts["LOW"]      * 1
    )
    if risk == 0:
        risk_label = "None"
    elif risk <= 5:
        risk_label = "Low"
    elif risk <= 15:
        risk_label = "Medium"
    elif risk <= 30:
        risk_label = "High"
    else:
        risk_label = "Critical"

    return {"counts": counts, "total": total, "risk": risk, "risk_label": risk_label}


# ─────────────────────────────────────────────────────────────────────────────
#  Dynamic OWASP coverage table
# ─────────────────────────────────────────────────────────────────────────────

_OWASP_TOP10 = [
    ("API1",  "Broken Object Level Authorization",
     {"REST": "IDOR, path traversal",           "GraphQL": "IDOR via queries",         "SOAP": "BOLA/IDOR on operations"},
     ["API1:2023"]),
    ("API2",  "Broken Authentication",
     {"REST": "JWT none/alg confusion, rate limit", "GraphQL": "Mutation auth bypass",  "SOAP": "WS-Security bypass, replay"},
     ["API2:2023"]),
    ("API3",  "Broken Object Property Level Authorization",
     {"REST": "Mass assignment, sensitive data", "GraphQL": "Sensitive field exposure", "SOAP": "SQLi, XPath injection"},
     ["API3:2023"]),
    ("API4",  "Unrestricted Resource Consumption",
     {"REST": "Rate limiting absent",            "GraphQL": "Depth/alias/batch attacks","SOAP": "XML DoS, billion laughs"},
     ["API4:2023"]),
    ("API5",  "Broken Function Level Authorization",
     {"REST": "BFLA, HTTP method tampering",     "GraphQL": "Mutation auth bypass",     "SOAP": "SOAPAction spoofing"},
     ["API5:2023"]),
    ("API6",  "Unrestricted Access to Sensitive Business Flows",
     {"REST": "Sensitive data in responses",     "GraphQL": "Field exposure",           "SOAP": "Fault disclosure"},
     ["API6:2023"]),
    ("API7",  "Server Side Request Forgery",
     {"REST": "SSRF via URL parameters",         "GraphQL": "N/A",                      "SOAP": "XXE-based SSRF"},
     ["API7:2023"]),
    ("API8",  "Security Misconfiguration",
     {"REST": "CORS, headers, error disclosure", "GraphQL": "Introspection, CSRF",      "SOAP": "WSDL exposure, XXE, cmd injection"},
     ["API8:2023"]),
    ("API9",  "Improper Inventory Management",
     {"REST": "Exposed docs, debug, old versions","GraphQL": "Schema exposure",          "SOAP": "WSDL disclosure"},
     ["API9:2023"]),
    ("API10", "Unsafe Consumption of APIs",
     {"REST": "SQLi, NoSQLi, XSS",              "GraphQL": "SQLi, NoSQLi",             "SOAP": "SQL/XML injection"},
     ["API10:2023"]),
]


def _render_owasp_table(findings: list[dict]) -> str:
    """Build a dynamic OWASP API Top 10 coverage table."""
    found_owasp: set[str] = set()
    for f in findings:
        owasp_val = f.get("owasp", "")
        if ":" in owasp_val:
            tag = owasp_val.split(" ")[0]
            found_owasp.add(tag)

    vuln_ids = [f.get("vuln_id", "") for f in findings]
    if any(v.startswith("GQL") for v in vuln_ids):
        api_type = "GraphQL"
    elif any(v.startswith("SOAP") for v in vuln_ids):
        api_type = "SOAP"
    else:
        api_type = "REST"

    tex = r"""\begin{center}
\begin{longtable}{p{1.1cm}p{5.5cm}p{4.5cm}p{2.5cm}}
\toprule
\rowcolor{TableHeader}
\textcolor{white}{\textbf{ID}} &
\textcolor{white}{\textbf{Category}} &
\textcolor{white}{\textbf{Test Coverage}} &
\textcolor{white}{\textbf{Status}} \\
\midrule
\endfirsthead
\toprule
\rowcolor{TableHeader}
\textcolor{white}{\textbf{ID}} &
\textcolor{white}{\textbf{Category}} &
\textcolor{white}{\textbf{Test Coverage}} &
\textcolor{white}{\textbf{Status}} \\
\midrule
\endhead
"""

    for api_id, category, coverage_map, owasp_tags in _OWASP_TOP10:
        coverage   = coverage_map.get(api_type, "N/A")
        is_vuln    = any(
            any(tag in oval for tag in owasp_tags)
            for oval in found_owasp
        )
        if is_vuln:
            status = r"\textcolor{CriticalRed}{\textbf{[!] Vulnerable}}"
        else:
            status = r"\textcolor{LowGreen}{-- Not Detected}"

        tex += (
            r"\textbf{" + api_id + r"} & "
            + _esc(category) + " & "
            + _esc(coverage) + " & "
            + status + r" \\" + "\n"
        )

    tex += r"""\bottomrule
\end{longtable}
\end{center}
"""
    return tex


# ─────────────────────────────────────────────────────────────────────────────
#  LaTeX template rendering
# ─────────────────────────────────────────────────────────────────────────────

def _render_tex(
    findings:   list[dict],
    discovery:  dict,
    author:     str,
    scan_date:  str,
) -> str:

    stats      = _compute_stats(findings)
    target_url = discovery.get("target_url", "Unknown")
    api_type   = discovery.get("api_type",   "Unknown")
    schema     = discovery.get("schema")     or {}
    n_queries  = len(schema.get("queries",   []))
    n_muts     = len(schema.get("mutations", []))

    tex = r"""
\documentclass[12pt,a4paper]{report}

\usepackage[T1]{fontenc}
\usepackage[utf8]{inputenc}
\usepackage{lmodern}
\usepackage[top=2.5cm, bottom=2.5cm, left=3cm, right=2.5cm]{geometry}
\usepackage{xcolor}
\usepackage{colortbl}
\usepackage{booktabs}
\usepackage{longtable}
\usepackage{array}
\usepackage{hyperref}
\usepackage{fancyhdr}
\usepackage{titlesec}
\usepackage{graphicx}
\usepackage{enumitem}
\usepackage{listings}
\usepackage{parskip}
\usepackage{mdframed}
\usepackage{tabularx}
\usepackage{multirow}
\usepackage{amsmath}
\usepackage{xurl}
\usepackage{tcolorbox}
\tcbuselibrary{skins,breakable}

\definecolor{APIsecBlue}{HTML}{1A3A5C}
\definecolor{APIsecAccent}{HTML}{2E86AB}
\definecolor{CriticalRed}{HTML}{BF0000}
\definecolor{HighOrange}{HTML}{D95F00}
\definecolor{MediumYellow}{HTML}{D4A017}
\definecolor{LowGreen}{HTML}{2E7D32}
\definecolor{InfoBlue}{HTML}{1565C0}
\definecolor{LightGray}{HTML}{F5F5F5}
\definecolor{TableHeader}{HTML}{1A3A5C}
\definecolor{TableRowAlt}{HTML}{EEF2F7}

\hypersetup{
    colorlinks   = true,
    linkcolor    = APIsecBlue,
    urlcolor     = APIsecAccent,
    citecolor    = APIsecBlue,
    pdftitle     = {APISec Security Report},
    breaklinks   = true,
    pdfauthor    = {APISec},
}

\pagestyle{fancy}
\fancyhf{}
\fancyhead[L]{\small\textcolor{APIsecBlue}{\textbf{APISec} --- API Security Audit Report}}
\fancyhead[R]{\small\textcolor{gray}{""" + _esc(scan_date) + r"""}}
\fancyfoot[C]{\small\textcolor{gray}{\thepage}}
\renewcommand{\headrulewidth}{0.4pt}
\renewcommand{\footrulewidth}{0pt}

\titleformat{\chapter}[block]
  {\normalfont\Large\bfseries\color{APIsecBlue}}
  {\thechapter.}{1em}{}
  [\vspace{-0.5em}\rule{\textwidth}{0.4pt}]

\titleformat{\section}
  {\normalfont\large\bfseries\color{APIsecBlue}}
  {\thesection}{1em}{}

\titleformat{\subsection}
  {\normalfont\normalsize\bfseries\color{APIsecAccent}}
  {\thesubsection}{1em}{}

\lstset{
    basicstyle   = \ttfamily\small,
    breaklines   = true,
    frame        = single,
    rulecolor    = \color{APIsecAccent},
    backgroundcolor = \color{LightGray},
    xleftmargin  = 5pt,
    xrightmargin = 5pt,
}

\tcbset{
    finding/.style={
        breakable,
        enhanced,
        colback=LightGray,
        colframe=APIsecBlue,
        fonttitle=\bfseries,
        left=6pt, right=6pt, top=4pt, bottom=4pt,
        before skip=10pt, after skip=6pt,
    }
}

\begin{document}
\pagenumbering{gobble}
"""

    # Cover page
    tex += r"""
\begin{titlepage}
\centering
\vspace*{2cm}

{\Huge\bfseries\color{APIsecBlue} APISec}\\[0.4em]
{\large\color{APIsecAccent} API Security Audit Report}\\[0.2em]
\rule{0.6\textwidth}{1pt}\\[2em]

\begin{tcolorbox}[colback=APIsecBlue!8, colframe=APIsecBlue, width=0.85\textwidth,
                  left=12pt, right=12pt, top=10pt, bottom=10pt]
\begin{tabular}{@{}p{2.5cm}p{9cm}}
\textbf{Target URL}  & \texttt{""" + _esc_url(target_url) + r"""} \\[4pt]
\textbf{API Type}    & """ + _esc(api_type) + r""" \\[4pt]
\textbf{Scan Date}   & """ + _esc(scan_date) + r""" \\[4pt]
\textbf{Author}      & """ + _esc(author) + r""" \\[4pt]
\textbf{Tool}        & APISec v1.0 --- REST $\cdot$ GraphQL $\cdot$ SOAP \\
\end{tabular}
\end{tcolorbox}

\vspace{2em}
"""

    risk_color_map = {
        "None":     "LowGreen",
        "Low":      "LowGreen",
        "Medium":   "MediumYellow",
        "High":     "HighOrange",
        "Critical": "CriticalRed",
    }
    risk_color = risk_color_map.get(stats["risk_label"], "InfoBlue")

    tex += r"""
\begin{tcolorbox}[colback=""" + risk_color + r"""!15, colframe=""" + risk_color + r""",
                  width=0.5\textwidth, center,
                  left=8pt, right=8pt, top=6pt, bottom=6pt]
\centering
{\large\bfseries Overall Risk Level}\\[4pt]
{\Huge\bfseries\color{""" + risk_color + r"""} """ + _esc(stats["risk_label"]) + r"""}
\end{tcolorbox}

\vspace{2em}

\begin{tabular}{ccccc}
"""

    sev_colors = {
        "CRITICAL": "CriticalRed",
        "HIGH":     "HighOrange",
        "MEDIUM":   "MediumYellow",
        "LOW":      "LowGreen",
        "INFO":     "InfoBlue",
    }

    for sev in _SEV_ORDER:
        count = stats["counts"][sev]
        color = sev_colors[sev]
        tex += (
            r"\begin{tcolorbox}[colback=" + color + r"!12, colframe=" + color +
            r", width=2.1cm, nobeforeafter, box align=top, left=2pt, right=2pt, top=3pt, bottom=3pt]"
            r"\centering{\fontsize{6}{7}\selectfont\bfseries " + sev + r"}\\[2pt]{\large\bfseries\color{" +
            color + r"} " + str(count) + r"}\end{tcolorbox} & "
        )
    tex = tex.rstrip(" & \n") + r""" \\
\end{tabular}

\vfill
{\small\color{gray} Generated by APISec --- Automated API Security Audit Tool}
\end{titlepage}
"""

    # TOC
    tex += r"""
\pagenumbering{roman}
\tableofcontents
\newpage
\pagenumbering{arabic}
"""

    # Chapter 1 — Executive Summary
    tex += r"""
\chapter{Executive Summary}

This report presents the results of an automated security audit conducted by
\textbf{APISec} against the target API. The audit covers the OWASP API Security
Top 10 (2023) vulnerability categories and applies active probing techniques
including introspection analysis, authentication bypass, injection testing,
and access control verification.

\section{Audit Scope}

\begin{tabular}{@{}p{3cm}p{10cm}}
\toprule
\textbf{Parameter} & \textbf{Value} \\
\midrule
Target URL   & \texttt{""" + _esc_url(target_url) + r"""} \\
API Type     & """ + _esc(api_type) + r""" \\
Scan Date    & """ + _esc(scan_date) + r""" \\
Total Findings & """ + str(stats["total"]) + r""" \\
"""

    if api_type == "GraphQL" and (n_queries or n_muts):
        tex += (
            r"Queries Tested  & " + str(n_queries) + r" \\" + "\n"
            r"Mutations Tested & " + str(n_muts) + r" \\" + "\n"
        )

    tex += r"""
\bottomrule
\end{tabular}

\section{Findings Summary}

\begin{center}
\begin{tabular}{lcc}
\toprule
\rowcolor{TableHeader}
\textcolor{white}{\textbf{Severity}} &
\textcolor{white}{\textbf{Count}} &
\textcolor{white}{\textbf{Risk Weight}} \\
\midrule
"""

    weight_map = {"CRITICAL": 10, "HIGH": 5, "MEDIUM": 2, "LOW": 1, "INFO": 0}
    for sev in _SEV_ORDER:
        count  = stats["counts"][sev]
        color  = sev_colors[sev]
        weight = weight_map[sev]
        if count > 0:
            tex += (
                r"\textcolor{" + color + r"}{\textbf{" + sev + r"}} & "
                + str(count) + r" & " + str(weight) + r" \\" + "\n"
            )

    tex += r"""
\midrule
\textbf{Total} & \textbf{""" + str(stats["total"]) + r"""} & \textbf{""" + str(stats["risk"]) + r"""} \\
\bottomrule
\end{tabular}
\end{center}

\section{Risk Assessment}

The overall risk level for this target is assessed as
\textbf{\textcolor{""" + risk_color + r"""}{""" + stats["risk_label"] + r"""}}
with a composite risk score of \textbf{""" + str(stats["risk"]) + r"""}.
"""

    if stats["counts"]["CRITICAL"] > 0:
        tex += (
            r"\textbf{" + str(stats["counts"]["CRITICAL"]) +
            r" critical vulnerability/vulnerabilities} require immediate remediation "
            r"as they may allow complete API compromise or data exfiltration." + "\n\n"
        )

    # Chapter 2 — Methodology
    tex += r"""
\chapter{Methodology}

\section{Testing Approach}

APISec follows a structured black-box testing methodology aligned with the
OWASP API Security Testing Guide. The audit is conducted in three phases:

\begin{enumerate}[leftmargin=2em]
  \item \textbf{Discovery} --- Automated detection of API type (REST, GraphQL, SOAP),
        endpoint enumeration via wordlist crawling, and schema extraction
        (Swagger/OpenAPI, GraphQL introspection, WSDL).

  \item \textbf{Scanning} --- Active vulnerability testing against discovered endpoints,
        applying test cases mapped to OWASP API Top 10 categories.

  \item \textbf{Reporting} --- Structured output with severity classification,
        OWASP/CWE mapping, evidence, and remediation guidance.
\end{enumerate}

\section{OWASP API Security Top 10 Coverage}

"""
    tex += _render_owasp_table(findings)

    # Chapter 3 — Detailed Findings
    tex += r"""
\chapter{Detailed Findings}

The following section details each vulnerability identified during the audit,
ordered by severity.

"""

    grouped: dict[str, list[dict]] = {s: [] for s in _SEV_ORDER}
    for f in findings:
        sev = f.get("severity", "INFO").upper()
        if sev in grouped:
            grouped[sev].append(f)

    finding_num = 1
    for sev in _SEV_ORDER:
        sev_findings = grouped[sev]
        if not sev_findings:
            continue

        color = sev_colors[sev]
        tex += (
            r"\section{\textcolor{" + color + r"}{"
            + sev + r" Severity Findings}}" + "\n\n"
        )

        for f in sev_findings:
            vuln_id   = _esc(f.get("vuln_id",   "N/A"))
            vuln_type = _esc(f.get("vuln_type",  "Unknown"))
            endpoint  = _esc_url(f.get("endpoint", "N/A"))
            method    = _esc(f.get("method",    "N/A"))
            parameter = _esc(f.get("parameter") or "N/A")
            payload   = _sanitize(f.get("payload") or "")
            evidence  = _esc(f.get("evidence",  "N/A"))
            desc      = _esc(f.get("description", ""))
            solution  = _esc(f.get("solution",    ""))
            owasp     = _esc(f.get("owasp",  "N/A"))
            cwe       = _esc(f.get("cwe",    "N/A"))
            conf      = _esc(f.get("confidence", "N/A"))
            ref       = _sanitize(f.get("reference", ""))

            tex += (
                r"\begin{tcolorbox}[finding, title={"
                r"\textbf{[" + vuln_id + r"]} " + vuln_type
                + r" \hfill \textcolor{" + color + r"}{"
                + sev + r"}}]" + "\n"
            )

            tex += r"""
\begin{tabularx}{\linewidth}{@{}p{3cm}X}
\textbf{Finding \#} & """ + str(finding_num) + r""" \\
\textbf{Endpoint}   & {\small\ttfamily\raggedright """ + endpoint + r"""} \\
\textbf{Method}     & \texttt{""" + method + r"""} \\
\textbf{Parameter}  & \texttt{""" + parameter + r"""} \\
\textbf{OWASP}      & """ + owasp + r""" \\
\textbf{CWE}        & """ + cwe + r""" \\
\textbf{Confidence} & """ + conf + r""" \\
\end{tabularx}

\medskip
\textbf{Description:}

""" + desc + r"""

\medskip
\textbf{Evidence:}

\begin{mdframed}[backgroundcolor=LightGray, linecolor=APIsecAccent, linewidth=0.5pt]
\small """ + evidence + r"""
\end{mdframed}
"""

            if payload:
                clean_payload = payload.replace("\n", " ")[:250]
                tex += r"""
\medskip
\textbf{Payload:}
\begin{lstlisting}
""" + clean_payload + r"""
\end{lstlisting}
"""

            tex += r"""
\medskip
\textbf{Remediation:}

""" + solution + "\n"

            if ref:
                tex += (
                    r"\medskip\textbf{Reference:} \url{"
                    + ref + r"}" + "\n"
                )

            tex += r"\end{tcolorbox}" + "\n\n"
            finding_num += 1

    # Chapter 4 — Recommendations
    tex += r"""
\chapter{Recommendations}

\section{Priority Remediation Plan}

Based on the findings, the following remediation actions are recommended
in order of priority:

"""

    priority = 1
    for sev in ["CRITICAL", "HIGH", "MEDIUM", "LOW"]:
        for f in grouped.get(sev, []):
            vuln_id  = _esc(f.get("vuln_id",  ""))
            solution = _esc(f.get("solution", ""))
            color    = sev_colors[sev]
            tex += (
                r"\noindent\textbf{" + str(priority) + r". ["
                + r"\textcolor{" + color + r"}{" + sev + r"}] "
                + _esc(f.get("vuln_type", "")) + r" (" + vuln_id + r")}\\[2pt]"
                + "\n" + solution + r"\\[6pt]" + "\n\n"
            )
            priority += 1

    tex += r"""
\section{Security Best Practices}

\begin{itemize}[leftmargin=2em]
  \item \textbf{Authentication \& Authorization:} Enforce authentication on all
        sensitive endpoints. Implement object-level and function-level authorization
        checks. Never rely on security through obscurity.

  \item \textbf{Input Validation:} Validate and sanitize all inputs server-side.
        Use parameterized queries to prevent injection attacks.

  \item \textbf{Rate Limiting:} Implement rate limiting and query complexity
        analysis to prevent denial-of-service via resource exhaustion.

  \item \textbf{Error Handling:} Return generic error messages in production.
        Never expose stack traces, internal paths, or framework details.

  \item \textbf{API Inventory:} Maintain an up-to-date inventory of all API
        endpoints. Disable debug endpoints, documentation, and admin interfaces
        in production environments.

  \item \textbf{Security Headers:} Enforce HTTPS, set strict CORS policies,
        and configure security headers (CSP, HSTS, X-Content-Type-Options).

  \item \textbf{Continuous Testing:} Integrate automated API security testing
        into the CI/CD pipeline. Re-run APISec after each major API change.
\end{itemize}
"""

    # Appendix
    tex += r"""
\chapter*{Appendix --- Vulnerability Reference}
\addcontentsline{toc}{chapter}{Appendix --- Vulnerability Reference}

\begin{center}
\begin{longtable}{llll}
\toprule
\rowcolor{TableHeader}
\textcolor{white}{\textbf{ID}} &
\textcolor{white}{\textbf{Type}} &
\textcolor{white}{\textbf{Severity}} &
\textcolor{white}{\textbf{OWASP}} \\
\midrule
\endfirsthead
\toprule
\rowcolor{TableHeader}
\textcolor{white}{\textbf{ID}} &
\textcolor{white}{\textbf{Type}} &
\textcolor{white}{\textbf{Severity}} &
\textcolor{white}{\textbf{OWASP}} \\
\midrule
\endhead
"""

    for f in findings:
        vuln_id   = _esc(f.get("vuln_id",   ""))
        vuln_type = _esc(f.get("vuln_type",  ""))
        sev       = f.get("severity", "INFO").upper()
        owasp     = _esc(f.get("owasp", ""))
        color     = sev_colors.get(sev, "InfoBlue")
        tex += (
            vuln_id + r" & " + vuln_type + r" & "
            r"\textcolor{" + color + r"}{\textbf{" + sev + r"}} & "
            + owasp + r" \\" + "\n"
        )

    tex += r"""
\bottomrule
\end{longtable}
\end{center}

\vfill
\begin{center}
\small\color{gray}
This report was generated automatically by \textbf{APISec v1.0}.\\
Results should be verified by a qualified security professional before
taking remediation actions.
\end{center}

\end{document}
"""
    return tex


# ─────────────────────────────────────────────────────────────────────────────
#  PDF compilation
# ─────────────────────────────────────────────────────────────────────────────

def _compile_pdf(tex_source: str, output_path: str) -> bool:
    import shutil

    pdflatex = shutil.which("pdflatex")
    if not pdflatex:
        raise RuntimeError(
            "pdflatex not found. Install it with:\n"
            "  sudo apt install texlive-latex-recommended texlive-latex-extra"
        )

    with tempfile.TemporaryDirectory(prefix="apisec_report_") as tmpdir:
        tex_path = os.path.join(tmpdir, "report.tex")
        pdf_path = os.path.join(tmpdir, "report.pdf")

        with open(tex_path, "w", encoding="utf-8") as f:
            f.write(tex_source)

        cmd = [
            pdflatex,
            "-interaction=nonstopmode",
            "-output-directory", tmpdir,
            tex_path,
        ]

        for pass_num in range(2):
            result = subprocess.run(
                cmd,
                capture_output = True,
                text           = True,
                encoding       = "utf-8",
                errors         = "replace",
                timeout        = 120,
                cwd            = tmpdir,
            )
            if result.returncode != 0 and pass_num == 1:
                log_file = os.path.join(tmpdir, "report.log")
                if os.path.isfile(log_file):
                    with open(log_file, "r", encoding="utf-8", errors="replace") as lf:
                        lines = lf.readlines()
                    errors = [l for l in lines if l.startswith("!")]
                    if errors:
                        raise RuntimeError(
                            "pdflatex compilation failed:\n" + "".join(errors[:10])
                        )

        if not os.path.isfile(pdf_path):
            raise RuntimeError("pdflatex did not produce a PDF file.")

        shutil.copy2(pdf_path, output_path)

    return True


# ─────────────────────────────────────────────────────────────────────────────
#  Public entry point
# ─────────────────────────────────────────────────────────────────────────────

def generate_report(
    scan_results_path:  str,
    output_path:        str,
    discovery_path:     Optional[str] = None,
    author:             str           = "APISec Audit Tool --- Automation of API Security Audit",
) -> str:
    findings  = _load_scan_results(scan_results_path)
    discovery = _load_discovery(discovery_path)
    scan_date = datetime.now().strftime("%B %d, %Y --- %H:%M")

    if not findings:
        raise ValueError(f"No findings found in '{scan_results_path}'.")

    if not discovery.get("target_url") and findings:
        from urllib.parse import urlparse
        first_ep = findings[0].get("endpoint", "")
        parsed   = urlparse(first_ep)
        if parsed.scheme and parsed.netloc:
            discovery["target_url"] = f"{parsed.scheme}://{parsed.netloc}"

    if not discovery.get("api_type") and findings:
        first_id = findings[0].get("vuln_id", "").upper()
        if first_id.startswith("GQL"):
            discovery["api_type"] = "GraphQL"
        elif any(first_id.startswith(p) for p in ("SOAP", "XXE", "WSDL")):
            discovery["api_type"] = "SOAP"
        else:
            discovery["api_type"] = "REST"

    tex = _render_tex(
        findings  = findings,
        discovery = discovery,
        author    = author,
        scan_date = scan_date,
    )

    abs_output = os.path.abspath(output_path)
    _compile_pdf(tex, abs_output)

    return abs_output