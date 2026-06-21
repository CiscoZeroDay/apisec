# core/report_generator.py
"""
APISec Report Generator — LaTeX-style PDF via pdflatex.

Usage (CLI):
    apisec report --input scan_results.json --output report.pdf
    apisec report --input scan_results.json --discovery endpoints.json --output report.pdf --author "John Doe"

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

def _esc(text: str) -> str:
    """Escape special LaTeX characters in plain text."""
    if not text:
        return ""
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
    """Escape URL for LaTeX — allow line breaks at / and - characters."""
    if not url:
        return ""
    # Insert zero-width break hints after / and - so LaTeX can wrap the URL
    escaped = url.replace("%", r"\%").replace("#", r"\#").replace("_", r"\_")
    # Insert \allowbreak after each / and . for natural line-breaking
    escaped = escaped.replace("/", r"/\allowbreak{}").replace(".", r".\allowbreak{}")
    return escaped


def _verbatim(text: str) -> str:
    """Wrap text in a LaTeX verbatim-safe box."""
    if not text:
        return r"\textit{N/A}"
    # Use \texttt with manual escaping for inline display
    cleaned = text.replace("\n", " ").replace("\r", "")[:300]
    return r"\texttt{" + _esc(cleaned) + r"}"


# ─────────────────────────────────────────────────────────────────────────────
#  Data loading
# ─────────────────────────────────────────────────────────────────────────────

def _load_scan_results(path: str) -> list[dict]:
    # errors="replace" — never crash on a stray non-UTF-8 byte in scan data
    # (e.g. a payload/evidence string captured from a scanned target).
    with open(path, "r", encoding="utf-8", errors="replace") as f:
        data = json.load(f)
    if isinstance(data, list):
        return data
    return []


def _load_discovery(path: Optional[str]) -> dict:
    if not path or not os.path.isfile(path):
        return {}
    try:
        # errors="replace" — same safety net as _load_scan_results.
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

    # Risk score: CRITICAL×10 + HIGH×5 + MEDIUM×2 + LOW×1
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

    # ── Preamble ──────────────────────────────────────────────────────────────
    tex = r"""
\documentclass[12pt,a4paper]{report}

% ── Packages ──────────────────────────────────────────────────────────────────
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
\usepackage{seqsplit}
\usepackage{xurl}
\usepackage{tcolorbox}
\tcbuselibrary{skins,breakable}

% ── Colors ────────────────────────────────────────────────────────────────────
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

% ── Hyperref setup ────────────────────────────────────────────────────────────
\hypersetup{
    colorlinks   = true,
    linkcolor    = APIsecBlue,
    urlcolor     = APIsecAccent,
    citecolor    = APIsecBlue,
    pdftitle     = {APISec Security Report},
    breaklinks   = true,
    pdfauthor    = {APISec},
}

% ── Header / Footer ───────────────────────────────────────────────────────────
\pagestyle{fancy}
\fancyhf{}
\fancyhead[L]{\small\textcolor{APIsecBlue}{\textbf{APISec} — API Security Audit Report}}
\fancyhead[R]{\small\textcolor{gray}{""" + _esc(scan_date) + r"""}}
\fancyfoot[C]{\small\textcolor{gray}{\thepage}}
\renewcommand{\headrulewidth}{0.4pt}
\renewcommand{\footrulewidth}{0pt}

% ── Section style ─────────────────────────────────────────────────────────────
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

% ── Listings (code/payload) ───────────────────────────────────────────────────
\lstset{
    basicstyle   = \ttfamily\small,
    breaklines   = true,
    frame        = single,
    rulecolor    = \color{APIsecAccent},
    backgroundcolor = \color{LightGray},
    xleftmargin  = 5pt,
    xrightmargin = 5pt,
}

% ── tcolorbox styles ──────────────────────────────────────────────────────────
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

    # ── Cover page ────────────────────────────────────────────────────────────
    tex += r"""
% ════════════════════════════════════════════════════════════════════
%  COVER PAGE
% ════════════════════════════════════════════════════════════════════
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
\textbf{Tool}        & APISec v1.0 — REST $\cdot$ GraphQL $\cdot$ SOAP \\
\end{tabular}
\end{tcolorbox}

\vspace{2em}

% Risk badge
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

% Severity summary table
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
    # Remove last " & " and close tabular
    tex = tex.rstrip(" & \n") + r""" \\
\end{tabular}

\vfill
{\small\color{gray} Generated by APISec — Automated API Security Audit Tool}
\end{titlepage}
"""

    # ── TOC ───────────────────────────────────────────────────────────────────
    tex += r"""
\pagenumbering{roman}
\tableofcontents
\newpage
\pagenumbering{arabic}
"""

    # ── Chapter 1 — Executive Summary ─────────────────────────────────────────
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
            r"Mutations Tested & " + str(n_muts)   + r" \\" + "\n"
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

    # ── Chapter 2 — Methodology ───────────────────────────────────────────────
    tex += r"""
\chapter{Methodology}

\section{Testing Approach}

APISec follows a structured black-box testing methodology aligned with the
OWASP API Security Testing Guide. The audit is conducted in three phases:

\begin{enumerate}[leftmargin=2em]
  \item \textbf{Discovery} — Automated detection of API type (REST, GraphQL, SOAP),
        endpoint enumeration via wordlist crawling, and schema extraction
        (Swagger/OpenAPI, GraphQL introspection, WSDL).

  \item \textbf{Scanning} — Active vulnerability testing against discovered endpoints,
        applying test cases mapped to OWASP API Top 10 categories.

  \item \textbf{Reporting} — Structured output with severity classification,
        OWASP/CWE mapping, evidence, and remediation guidance.
\end{enumerate}

\section{OWASP API Security Top 10 Coverage}

\begin{center}
\begin{tabular}{lll}
\toprule
\rowcolor{TableHeader}
\textcolor{white}{\textbf{ID}} &
\textcolor{white}{\textbf{Category}} &
\textcolor{white}{\textbf{Test Coverage}} \\
\midrule
API1  & Broken Object Level Authorization   & IDOR, GraphQL query enumeration \\
API2  & Broken Authentication               & JWT attacks, token bypass \\
API3  & Broken Object Property Level Auth   & Mass assignment, field exposure \\
API4  & Unrestricted Resource Consumption   & Depth/alias/batch attacks \\
API5  & Broken Function Level Authorization & BFLA, mutation auth bypass \\
API6  & Unrestricted Access to Sensitive    & Sensitive data in responses \\
API7  & Server Side Request Forgery         & SSRF via URL parameters \\
API8  & Security Misconfiguration           & CORS, headers, introspection \\
API9  & Improper Inventory Management       & Exposed docs, debug endpoints \\
API10 & Unsafe Consumption of APIs          & Injection (SQLi, NoSQLi, XSS) \\
\bottomrule
\end{tabular}
\end{center}
"""

    # ── Chapter 3 — Detailed Findings ─────────────────────────────────────────
    tex += r"""
\chapter{Detailed Findings}

The following section details each vulnerability identified during the audit,
ordered by severity.

"""

    # Group by severity
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
            payload   = f.get("payload")   or ""
            evidence  = _esc(f.get("evidence",  "N/A"))
            desc      = _esc(f.get("description", ""))
            solution  = _esc(f.get("solution",    ""))
            owasp     = _esc(f.get("owasp",  "N/A"))
            cwe       = _esc(f.get("cwe",    "N/A"))
            conf      = _esc(f.get("confidence", "N/A"))
            ref       = f.get("reference", "")

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
                    + ref.replace("%", r"\%") + r"}" + "\n"
                )

            tex += r"\end{tcolorbox}" + "\n\n"
            finding_num += 1

    # ── Chapter 4 — Recommendations ───────────────────────────────────────────
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

    # ── Appendix ──────────────────────────────────────────────────────────────
    tex += r"""
\chapter*{Appendix — Vulnerability Reference}
\addcontentsline{toc}{chapter}{Appendix — Vulnerability Reference}

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
    """
    Write tex_source to a temp file, compile twice with pdflatex,
    then move the result to output_path.

    Two passes are needed for correct TOC page numbers.
    """
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

        # Two passes for TOC
        for pass_num in range(2):
            result = subprocess.run(
                cmd,
                capture_output = True,
                text           = True,
                # FIX — force UTF-8 decoding of pdflatex's stdout/stderr instead
                # of relying on the system's default locale encoding. Without
                # this, any non-ASCII character surfacing in pdflatex's console
                # output (e.g. from a finding's evidence/payload echoed back in
                # an error message) raised:
                #   UnicodeDecodeError: 'utf-8' codec can't decode byte 0xe2 ...
                # `errors="replace"` guarantees this call never crashes the
                # report generation pipeline, even on a malformed byte.
                encoding       = "utf-8",
                errors         = "replace",
                timeout        = 120,
                cwd            = tmpdir,
            )
            if result.returncode != 0 and pass_num == 1:
                # Show last 20 lines of log for debugging
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
    author:             str           = "APISec Audit Tool — Automation of API Security Audit",
) -> str:
    """
    Generate a LaTeX-style PDF security report.

    Args:
        scan_results_path : path to scan_results.json
        output_path       : destination PDF path
        discovery_path    : path to endpoints.json (optional — for target info)
        author            : report author name (default: Security Analyst)

    Returns:
        Absolute path to the generated PDF.
    """
    findings  = _load_scan_results(scan_results_path)
    discovery = _load_discovery(discovery_path)
    scan_date = datetime.now().strftime("%B %d, %Y — %H:%M")

    if not findings:
        raise ValueError(f"No findings found in '{scan_results_path}'.")

    # Auto-detect target URL and API type from scan results
    # if discovery file not provided or missing fields
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