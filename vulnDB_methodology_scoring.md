# 🔐 VulnDB Severity Rating Methodology — APISEC

> **Reference:** [OWASP API Security Risk Rating](https://owasp.org/API-Security/editions/2023/en/0x10-api-security-risks/)

---

## 📋 Table of Contents

1. [Overview](#overview)
2. [Why NOT Likelihood × Impact](#why-not-likelihood--impact)
3. [The OWASP Four-Factor Methodology](#the-owasp-four-factor-methodology)
4. [Why These 4 Factors Are Right for APISEC](#why-these-4-factors-are-right-for-apisec)
5. [Business Impact Adjustment](#business-impact-adjustment)
6. [Scoring Examples](#scoring-examples)
7. [Summary](#summary)

---

## 1. 🎯 Overview

Severity levels in the APISEC VulnDB are assigned based on the **OWASP API Security Risk Rating**, as defined in the OWASP API Security Top 10 2023 edition.

The formula used is:

```
Score = (Exploitability + Prevalence + Detectability + Technical Impact) / 4
```

| Severity | Score | Color |
|---|---|---|
| 🔴 **CRITICAL** | ≥ 2.5 | Immediate action required |
| 🟠 **HIGH** | ≥ 2.0 | Fix as soon as possible |
| 🟡 **MEDIUM** | ≥ 1.5 | Plan remediation |
| 🟢 **LOW** | ≥ 1.0 | Monitor and review |
| ⚪ **INFO** | < 1.0 | Informational only |

---

## 2. ❌ Why NOT Likelihood × Impact ?

Many risk frameworks (including classic CVSS) compute severity as:

```
Score = Likelihood × Impact
```

This approach was **not adopted in APISEC** for four key reasons:

---

### 🚫 Reason 1 — Likelihood is contextual and unknown to the scanner

Likelihood depends on:
- Who is attacking *(script kiddie vs. nation-state actor)*
- Whether the API is exposed on the internet or internal network
- Whether the target is actively being targeted or not

> ⚠️ An automated tool like APISEC scans unknown APIs without any organizational context.
> It **cannot determine** the real Likelihood of exploitation for a given target.

---

### 🚫 Reason 2 — Business Impact is organization-specific

The same vulnerability has completely different Business Impact depending on the target:

| 🏢 Target | 🐛 Vulnerability | 💥 Business Impact |
|---|---|---|
| 🏦 Bank | SQL Injection | 🔴 CRITICAL — PCI-DSS, financial data, regulatory fines |
| 📝 Personal blog | SQL Injection | 🟢 LOW — no sensitive data, no regulation |
| 🏥 Hospital | SQL Injection | 🔴 CRITICAL — HIPAA, patient data |

> ⚠️ APISEC does not know the target's industry, applicable regulations, or data sensitivity.
> Assigning a Business Impact would be **arbitrary and misleading**.

---

### 🚫 Reason 3 — OWASP itself excludes Likelihood and Business Impact

The official OWASP API Security Risk page states explicitly:

> *"This approach does not take the likelihood of the threat agent into account.
> Nor does it account for any of the various technical details associated with
> your particular application. This rating does not take into account the actual
> impact on your business."*

✅ Our methodology is therefore **fully aligned with the official OWASP stance**.

---

### 🚫 Reason 4 — Multiplicative formula produces inconsistent results

| Scenario | Likelihood | Impact | L × I Score | Reality |
|---|---|---|---|---|
| Easy exploit, low business impact | High | Low | **Low** ❌ | Should be flagged |
| Hard exploit, catastrophic impact | Low | High | **Low** ❌ | Misleading |
| Easy exploit, high impact | High | High | **High** ✅ | Correct |

> The four-factor **average** avoids this problem by treating all factors equally
> and never allowing one factor to collapse the final score.

---

## 3. 📐 The OWASP Four-Factor Methodology

```
Score = (Exploitability + Prevalence + Detectability + Technical Impact) / 4
```

### Factor Scoring Table

| Factor | 3 ⬆️ | 2 ➡️ | 1 ⬇️ |
|---|---|---|---|
| **Exploitability** | Easy | Average | Difficult |
| **Prevalence** | Widespread | Common | Difficult |
| **Detectability** | Easy | Average | Difficult |
| **Technical Impact** | Severe | Moderate | Minor |

### Severity Thresholds

| Score Range | Severity |
|---|---|
| 2.50 — 3.00 | 🔴 **CRITICAL** |
| 2.00 — 2.49 | 🟠 **HIGH** |
| 1.50 — 1.99 | 🟡 **MEDIUM** |
| 1.00 — 1.49 | 🟢 **LOW** |

---

## 4. ✅ Why These 4 Factors Are Right for APISEC

These four factors are **intrinsic properties of the vulnerability itself**,
not of the target organization.

---

### 🔧 Exploitability — *"How hard is it to exploit?"*

> A **technical constant** — does not change depending on who owns the API.

| Example | Score | Reason |
|---|---|---|
| SQL Injection | 3 — Easy | Any attacker with a basic payload can exploit it |
| JWT Algorithm Confusion | 2 — Average | Requires specific cryptographic knowledge |
| XXE via OOB channel | 1 — Difficult | Requires external infrastructure setup |

---

### 📊 Prevalence — *"How common is this vulnerability?"*

> Based on **OWASP industry-wide statistical consensus** — not target-specific.

| Example | Score | Reason |
|---|---|---|
| BOLA / IDOR | 3 — Widespread | OWASP #1 most common API vulnerability |
| Mass Assignment | 2 — Common | Present in many frameworks by default |
| OS Command Injection | 1 — Difficult | Rare in modern APIs |

---

### 🔍 Detectability — *"How easy is it to detect?"*

> The factor **APISEC controls most directly** — it measures exactly what the scanner does.

| Example | Score | Reason |
|---|---|---|
| Introspection Exposed | 3 — Easy | One `__schema` query is enough |
| WSDL Exposure | 3 — Easy | Direct HTTP GET to `?wsdl` |
| Time-based SQLi | 2 — Average | Requires timing analysis across multiple requests |
| Blind SSRF | 1 — Difficult | Requires external callback infrastructure |

---

### 💥 Technical Impact — *"What is the technical damage?"*

> **Objective and independent of business context** — always true regardless of target.

| Example | Score | Reason |
|---|---|---|
| SQL Injection | 3 — Severe | Full database access |
| SSRF Cloud Metadata | 3 — Severe | Cloud credential theft |
| CORS Misconfiguration | 2 — Moderate | Session data readable cross-origin |
| Missing X-Content-Type | 1 — Minor | Low technical impact |

---

## 5. ⚖️ Business Impact Adjustment

Although the four-factor formula is more robust than Likelihood × Impact,
it can still **over-escalate** low-impact findings when Detectability is Easy (3).

### Example of Over-escalation Without Adjustment

| ID | Vulnerability | E | P | D | I | Raw Score | Raw Severity | Adjusted |
|---|---|---|---|---|---|---|---|---|
| INFO-001 | Server Version Disclosure | 3 | 3 | 3 | 1 | 2.50 | CRITICAL ❌ | 🟢 LOW ✅ |
| SOAP-01 | WSDL Exposure | 3 | 3 | 3 | 1 | 2.50 | CRITICAL ❌ | 🟡 MEDIUM ✅ |
| ERR-001 | Verbose Error Exposure | 3 | 3 | 3 | 1 | 2.50 | CRITICAL ❌ | 🟡 MEDIUM ✅ |

### Adjustment Rule

> When **Technical Impact = Minor (1)** AND the vulnerability requires
> **chaining with other attacks** to cause real damage →
> **downgrade one severity level**.

This is consistent with how industry tools classify the same categories:

| Tool | Server Version Disclosure | Missing Headers |
|---|---|---|
| Burp Suite | 🟢 Low / Info | 🟢 Low |
| OWASP ZAP | 🟢 Low | 🟢 Low |
| Nessus | 🟢 Low / Info | 🟢 Low |
| **APISEC** | 🟢 Low ✅ | 🟢 Low / Medium ✅ |

---

## 6. 📊 Scoring Examples

### 🔴 CRITICAL Vulnerabilities

| ID | Vulnerability | E | P | D | I | Score |
|---|---|---|---|---|---|---|
| SQLI-001 | SQL Injection | 3 | 2 | 3 | 3 | **2.75** |
| AUTH-003 | JWT none Algorithm | 3 | 1 | 3 | 3 | **2.50** |
| SOAP-02 | XXE Injection | 3 | 2 | 3 | 3 | **2.75** |
| GQL-S4 | Broken Auth on Mutations | 3 | 2 | 3 | 3 | **2.75** |
| NOSQL-001 | NoSQL Auth Bypass | 3 | 2 | 3 | 3 | **2.75** |
| SSRF-001 | SSRF Cloud Metadata | 3 | 1 | 3 | 3 | **2.50** |

### 🟠 HIGH Vulnerabilities *(Business Impact Adjustment applied)*

| ID | Vulnerability | E | P | D | I | Score | Note |
|---|---|---|---|---|---|---|---|
| IDOR-001 | BOLA / IDOR | 3 | 3 | 3 | 2 | 2.75 | Adjusted from CRITICAL |
| BFLA-001 | HTTP Method Tampering | 3 | 2 | 3 | 3 | 2.75 | Adjusted from CRITICAL |
| GQL-S11 | Depth Attack DoS | 3 | 2 | 3 | 2 | 2.50 | Adjusted from CRITICAL |

### 🟡 MEDIUM Vulnerabilities *(Business Impact Adjustment applied)*

| ID | Vulnerability | E | P | D | I | Score | Note |
|---|---|---|---|---|---|---|---|
| GQL-S1 | Introspection Exposed | 3 | 2 | 3 | 1 | 2.25 | Info disclosure only |
| SOAP-01 | WSDL Exposure | 3 | 3 | 3 | 1 | 2.50 | Adjusted from CRITICAL |
| ERR-001 | Verbose Error Exposure | 3 | 3 | 3 | 1 | 2.50 | Adjusted from CRITICAL |

### 🟢 LOW Vulnerabilities *(Business Impact Adjustment applied)*

| ID | Vulnerability | E | P | D | I | Score | Note |
|---|---|---|---|---|---|---|---|
| INFO-001 | Server Version Disclosure | 3 | 3 | 3 | 1 | 2.50 | Recon only, no direct exploit |
| INFO-002 | X-Powered-By Disclosure | 3 | 3 | 3 | 1 | 2.50 | Recon only, no direct exploit |
| HDR-002 | Missing X-Content-Type | 2 | 3 | 3 | 1 | 2.25 | Very low real-world impact |

---

## 7. 📋 Summary

| Criterion | ❌ Likelihood × Impact | ✅ OWASP 4 Factors (APISEC) |
|---|---|---|
| Formula | Multiplication | Average |
| Likelihood required | ✅ Yes | ❌ No |
| Business Impact required | ✅ Yes | ❌ No (Business Specific) |
| Needs organizational context | ✅ Yes | ❌ No |
| Suitable for automated tool | ❌ No | ✅ Yes |
| Consistent across vuln types | ❌ No | ✅ Yes |
| Aligned with OWASP API Top 10 | ⚠️ Partially | ✅ Fully |

---

> 💡 **Conclusion:**
> The OWASP four-factor methodology was chosen for APISEC because all four factors
> are **technical constants or directly measurable by the scanner**,
> requiring no organizational context. This makes severity ratings **objective,
> reproducible, and consistent** across all scanned targets — regardless of industry,
> regulation, or data sensitivity.

---

*Document generated for APISEC PFE Report — ENSAT Tanger / DATAPROTECT Casablanca*
*Author: RAZAFINDRAIBE Hery Jhonny — 2026*