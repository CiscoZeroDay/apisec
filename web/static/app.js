/**
 * APISec — app.js  v2.1
 * - Full English UI
 * - Dynamic test grid: switches per API type (REST / GraphQL / SOAP)
 *   matching exactly the CLI test registries in main.py
 */

"use strict";

// ═══════════════════════════════════════════════════════════════════════════
// TEST REGISTRY  — mirrors main.py  _TEST_REGISTRY exactly
// Each entry: { value, name, desc, owasp }
// ═══════════════════════════════════════════════════════════════════════════

const TESTS_BY_TYPE = {

  REST: [
    {
      value: "misconfig",
      name:  "Security Misconfiguration",
      owasp: "API7",
      checks: ["CORS-001 — Wildcard Access-Control-Allow-Origin",
               "CORS-002 — Reflected Origin without validation",
               "CORS-003 — CORS with credentials exposed",
               "HDR-001 — Missing X-Content-Type-Options",
               "HDR-002 — Missing X-Frame-Options",
               "HDR-003 — Missing Strict-Transport-Security",
               "HDR-004 — Missing Content-Security-Policy",
               "INFO-001 — Server version disclosure in headers",
               "INFO-002 — Stack trace / debug info in response",
               "VERB-001 — Dangerous HTTP methods enabled (PUT/DELETE/TRACE)",
               "ERR-001 — Verbose error messages"],
    },
    {
      value: "auth",
      name:  "Broken Authentication",
      owasp: "API2",
      checks: ["AUTH-001 — JWT algorithm confusion (RS256→HS256)",
               "AUTH-002 — JWT none algorithm accepted",
               "AUTH-003 — JWT with expired token still accepted",
               "AUTH-004 — JWT with invalid signature accepted",
               "AUTH-005 — Brute-force / rate limit bypass on auth endpoint"],
    },
    {
      value: "sqli",
      name:  "SQL Injection",
      owasp: "API8",
      checks: ["SQLI-001 — SQL Injection via sqlmap (error-based, union, boolean)"],
    },
    {
      value: "blind_sqli",
      name:  "Blind SQL Injection",
      owasp: "API8",
      checks: ["SQLI-002 — Blind SQL Injection (boolean-based)",
               "SQLI-003 — Time-based SQL Injection (sleep/benchmark)"],
    },
    {
      value: "nosql",
      name:  "NoSQL Injection",
      owasp: "API8",
      checks: ["NOSQL-001 — MongoDB $ne operator injection",
               "NOSQL-002 — MongoDB $gt / $lt operator injection",
               "NOSQL-003 — MongoDB $where JavaScript injection"],
    },

    {
      value: "idor",
      name:  "Broken Object Level Auth",
      owasp: "API1",
      checks: ["IDOR-001 — Numeric ID manipulation (id±1 to id±10)",
               "IDOR-002 — UUID/GUID enumeration",
               "IDOR-003 — Cross-account object access (requires --second-token)"],
    },
    {
      value: "ssrf",
      name:  "Server-Side Request Forgery",
      owasp: "API7",
      checks: ["SSRF-001 — In-Band SSRF via URL parameter",
               "SSRF-002 — Cloud metadata endpoint probe (169.254.169.254)",
               "SSRF-003 — Localhost / internal network probe",
               "SSRF-004 — DNS rebinding detection"],
    },
    {
      value: "mass_assign",
      name:  "Mass Assignment",
      owasp: "API3",
      checks: ["MASS-001 — Mass Assignment via undocumented fields (role, isAdmin, privilege…)"],
    },
    {
      value: "rate_limit",
      name:  "Unrestricted Resource Consumption",
      owasp: "API4",
      checks: ["RATE-001 — Absence of rate limiting on sensitive endpoints",
               "RATE-002 — Rate limit bypass via header manipulation (X-Forwarded-For)"],
    },
    {
      value: "inventory",
      name:  "Improper Inventory Management",
      owasp: "API9",
      checks: ["INV-001 — Exposed Swagger / OpenAPI documentation",
               "INV-002 — Exposed debug endpoints (/debug, /trace, /actuator)",
               "INV-003 — Exposed admin endpoints (/admin, /management)",
               "INV-004 — Old API versions still accessible (/v1, /v2…)"],
    },
    {
      value: "sensitive",
      name:  "Sensitive Data Exposure",
      owasp: "API3",
      checks: ["SENS-001 to 017 — Password / secret detection in responses",
               "SENS — API keys (AWS, GCP, Stripe, Twilio…)",
               "SENS — PII data (emails, phone numbers, SSN, credit cards)",
               "SENS — Cloud provider metadata & credentials",
               "SENS — Private keys & certificates in responses"],
    },
    {
      value: "bflaw",
      name:  "Broken Function Level Auth",
      owasp: "API5",
      checks: ["BFLA-001 — HTTP method tampering (GET→POST/PUT/DELETE)",
               "BFLA-002 — Unauthorized access to admin-level endpoints"],
    },
  ],

  GRAPHQL: [
    {
      value: "introspection",
      name:  "Schema Introspection",
      owasp: "API7",
      checks: ["GQL-001 — Schema introspection enabled in production",
               "GQL-002 — Full type system exposed via __schema query"],
    },
    {
      value: "bypass",
      name:  "Authentication Bypass",
      owasp: "API2",
      checks: ["GQL-003 — Auth bypass via field aliasing",
               "GQL-004 — Auth bypass via query batching"],
    },
    {
      value: "fields",
      name:  "Sensitive Field Exposure",
      owasp: "API3",
      checks: ["GQL-005 — Sensitive field exposure (passwords, tokens, secrets)",
               "GQL-006 — Hidden / internal fields accessible"],
    },
    {
      value: "auth",
      name:  "Broken Object Authorization",
      owasp: "API1",
      checks: ["GQL-007 — Missing object-level authorization on queries",
               "GQL-008 — Missing field-level authorization"],
    },
    {
      value: "idor",
      name:  "Broken Object Level Auth",
      owasp: "API1",
      checks: ["GQL-009 — Insecure Direct Object Reference via GraphQL ID arguments"],
    },
    {
      value: "csrf",
      name:  "Cross-Site Request Forgery",
      owasp: "API2",
      checks: ["GQL-010 — CSRF on mutations via GET request"],
    },


    {
      value: "batch",
      name:  "Batch Query Abuse",
      owasp: "API4",
      checks: ["GQL-013 — Batch query abuse leading to DoS",
               "GQL-014 — Unbounded query execution"],
    },
    {
      value: "alias",
      name:  "Alias Rate Limit Bypass",
      owasp: "API4",
      checks: ["GQL-015 — Alias-based rate limit bypass (10+ aliases in one request)"],
    },
    {
      value: "depth",
      name:  "Unbounded Query Depth",
      owasp: "API4",
      checks: ["GQL-016 — Unbounded query depth (deeply nested queries)",
               "GQL-017 — Query complexity not enforced"],
    },

    {
      value: "error",
      name:  "Verbose Error Disclosure",
      owasp: "API7",
      checks: ["GQL-020 — Verbose error messages leaking stack traces",
               "GQL-021 — Internal field names / schema details in errors"],
    },
  ],

  SOAP: [
    {
      value: "wsdl",
      name:  "WSDL Enumeration",
      owasp: "API7",
      checks: ["SOAP-001 — WSDL publicly accessible without authentication",
               "SOAP-002 — Service enumeration via WSDL (operations, types, bindings)"],
    },
    {
      value: "xxe",
      name:  "XML External Entity (XXE)",
      owasp: "API8",
      checks: ["SOAP-003 — XML External Entity (XXE) injection via SOAP body",
               "SOAP-004 — Blind XXE via out-of-band channel"],
    },
    {
      value: "sqli",
      name:  "SQL Injection",
      owasp: "API8",
      checks: ["SOAP-005 — SQL Injection in SOAP operation parameters"],
    },
    {
      value: "injection",
      name:  "XML / SOAP Injection",
      owasp: "API8",
      checks: ["SOAP-006 — XML Injection in SOAP body",
               "SOAP-007 — SOAP Parameter Tampering"],
    },
    {
      value: "auth",
      name:  "Broken Authentication",
      owasp: "API2",
      checks: ["SOAP-008 — Missing WS-Security header",
               "SOAP-009 — Weak / cleartext credentials in WS-Security UsernameToken"],
    },
    {
      value: "replay",
      name:  "Replay Attack",
      owasp: "API2",
      checks: ["SOAP-010 — Replay attack (missing Timestamp or Nonce in WS-Security)",
               "SOAP-011 — Message replay accepted after expiry"],
    },
    {
      value: "action_spoofing",
      name:  "SOAPAction Spoofing",
      owasp: "API1",
      checks: ["SOAP-012 — SOAPAction header spoofing (mismatch between header and body action)"],
    },
  ],
};

// ═══════════════════════════════════════════════════════════════════════════
// CONSTANTS
// ═══════════════════════════════════════════════════════════════════════════

const SEV_ORDER  = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"];
const SEV_ICONS  = { CRITICAL: "☠", HIGH: "⚡", MEDIUM: "◆", LOW: "●", INFO: "ℹ" };
const METHOD_CLS = {
  GET:"method-get", POST:"method-post", PUT:"method-put",
  DELETE:"method-delete", PATCH:"method-patch",
};

// ═══════════════════════════════════════════════════════════════════════════
// UTILITIES
// ═══════════════════════════════════════════════════════════════════════════

const esc = (s) =>
  s == null ? "—"
  : String(s)
    .replace(/&/g,"&amp;").replace(/</g,"&lt;")
    .replace(/>/g,"&gt;").replace(/"/g,"&quot;");

const fmtDur = (sec) => {
  if (!sec) return "—";
  return sec < 60 ? `${sec.toFixed(1)}s` : `${Math.floor(sec/60)}m ${(sec%60).toFixed(0)}s`;
};

const fmtDate = (iso) => {
  if (!iso) return "—";
  try {
    return new Date(iso).toLocaleString("en-GB", {
      day:"2-digit", month:"2-digit", year:"numeric",
      hour:"2-digit", minute:"2-digit", second:"2-digit",
    });
  } catch { return iso.slice(0,19).replace("T"," "); }
};

function notify(msg, type = "info") {
  const n    = document.createElement("div");
  n.className = `notif notif-${type}`;
  n.textContent = msg;
  document.body.appendChild(n);
  requestAnimationFrame(() => n.classList.add("show"));
  setTimeout(() => { n.classList.remove("show"); setTimeout(() => n.remove(), 300); }, 3500);
}

// ═══════════════════════════════════════════════════════════════════════════
// DYNAMIC TEST GRID  — the key new feature
// ═══════════════════════════════════════════════════════════════════════════

/**
 * Rebuild the #tests-grid content for the given API type.
 * Preserves the ALL checkbox first, then renders per-type tests.
 * Resets all selections to "ALL checked" on each switch.
 */
function renderTests(apiType) {
  const grid  = document.getElementById("tests-grid");
  const pill  = document.getElementById("tests-api-pill");
  if (!grid) return;

  const tests = TESTS_BY_TYPE[apiType] || TESTS_BY_TYPE.REST;

  // Update pill color
  if (pill) {
    pill.textContent  = apiType;
    pill.className    = `api-type-pill pill-${apiType.toLowerCase()}`;
  }

  // Build HTML
  // Row 0: ALL checkbox
  let html = `
    <label class="check-opt all-check" title="Run every test available for ${apiType}">
      <input type="checkbox" id="chk-all" checked aria-label="All tests"/>
      <span class="check-content">
        <span class="check-header">
          <span class="check-name">ALL</span>
          <span class="owasp-tag">ALL ${tests.length} TESTS</span>
        </span>
        <span class="check-desc">Run every implemented ${apiType} check</span>
      </span>
    </label>`;

  // Individual tests with expandable check list
  tests.forEach(t => {
    const checkItems = (t.checks || [])
      .map(c => `<li class="chk-item">${esc(c)}</li>`)
      .join("");

    html += `
    <label class="check-opt test-card">
      <input type="checkbox" class="test-chk" value="${t.value}"
             aria-label="${t.name}"/>
      <span class="check-content">
        <span class="check-header">
          <span class="check-name">${t.name}</span>
          <span class="owasp-tag">${t.owasp}</span>
          <span class="check-count">${t.checks ? t.checks.length : 0} check${(t.checks||[]).length > 1 ? "s" : ""}</span>
        </span>
        <ul class="chk-list">${checkItems}</ul>
      </span>
    </label>`;
  });

  grid.innerHTML = html;

  // Re-wire the ALL checkbox logic
  initCheckboxes();
}

// ═══════════════════════════════════════════════════════════════════════════
// FINDING CARD BUILDER  (shared index + history)
// ═══════════════════════════════════════════════════════════════════════════

function buildFindingCard(f) {
  const sev    = (f.severity || "INFO").toUpperCase();
  const method = (f.method   || "GET").toUpperCase();
  const mCls   = METHOD_CLS[method] || "method-other";

  const rows = [
    ["endpoint",    f.endpoint,    "mono"],
    ["owasp",       f.owasp,       ""],
    ["cwe",         f.cwe,         "mono"],
    ["confidence",  f.confidence,  ""],
    ["parameter",   f.parameter,   "mono"],
    ["payload",     f.payload,     "payload"],
    ["evidence",    f.evidence,    "evidence"],
    ["description", f.description, "description"],
    ["solution",    f.solution,    "solution"],
    ["reference",   f.reference,   "ref"],
  ].filter(([, v]) => v);

  const detailRows = rows.map(([k, v, cls]) => `
    <div class="detail-row">
      <div class="dk">${k}</div>
      <div class="dv ${cls}">${
        k === "reference"
          ? `<a href="${esc(v)}" target="_blank" rel="noopener">${esc(v)}</a>`
          : esc(String(v).slice(0, 600))
      }</div>
    </div>`
  ).join("");

  return `
  <div class="finding-card sev-${sev.toLowerCase()}" data-sev="${sev}">
    <div class="fc-header" onclick="toggleCard(this)">
      <span class="fc-sev-badge">${SEV_ICONS[sev] || "·"} ${sev}</span>
      <span class="fc-vuln-id">${esc(f.vuln_id)}</span>
      <span class="fc-type">${esc(f.vuln_type || "Unknown Vulnerability")}</span>
      <span class="fc-method ${mCls}">${esc(method)}</span>
      <span class="fc-endpoint">${esc(f.endpoint)}</span>
      <button class="fc-expand-btn" aria-label="Expand" tabindex="-1">+</button>
    </div>
    <div class="fc-body">
      <div class="detail-grid">${detailRows || '<div class="dk">info</div><div class="dv">No additional details.</div>'}</div>
    </div>
  </div>`;
}

function toggleCard(header) {
  const body   = header.closest(".finding-card").querySelector(".fc-body");
  const btn    = header.querySelector(".fc-expand-btn");
  const isOpen = body.classList.contains("open");
  body.classList.toggle("open", !isOpen);
  btn.textContent = isOpen ? "+" : "−";
}

// ═══════════════════════════════════════════════════════════════════════════
// MODAL  (shared)
// ═══════════════════════════════════════════════════════════════════════════

function initModal() {
  const overlay = document.getElementById("modal-overlay");
  if (!overlay) return;
  document.getElementById("modal-close").onclick = closeModal;
  overlay.onclick = (e) => { if (e.target === overlay) closeModal(); };
  document.addEventListener("keydown", (e) => { if (e.key === "Escape") closeModal(); });
}

function closeModal() {
  const o = document.getElementById("modal-overlay");
  if (o) o.style.display = "none";
}

// ═══════════════════════════════════════════════════════════════════════════
// ═══════════════════════════════════════════════════════════════════════════
// INDEX PAGE
// ═══════════════════════════════════════════════════════════════════════════
// ═══════════════════════════════════════════════════════════════════════════

let _scanId      = null;
let _evtSource   = null;
let _timerHandle = null;
let _timerSecs   = 0;
let _allFindings = [];
let _sevFilter   = "all";

function isIndexPage() { return !!document.getElementById("btn-launch"); }

async function initIndexPage() {
  // Default: AUTO selected → render REST tests as preview
  // (discovery will decide the real type at runtime)
  renderTests("REST");

  // ── API Type radio → update test grid when user forces a type ──────────
  document.getElementById("api-type-group").addEventListener("change", (e) => {
    if (e.target.name !== "api_type") return;
    const val = e.target.value;
    // AUTO = user wants discovery to decide → show REST tests as default preview
    renderTests(val === "AUTO" ? "REST" : val);

    // Visual hint on Auto option
    const autoLabel = document.getElementById("radio-auto-label");
    if (autoLabel) {
      autoLabel.classList.toggle("auto-active", val === "AUTO");
    }
  });

  // Trigger initial state for Auto label
  const autoLabel = document.getElementById("radio-auto-label");
  if (autoLabel) autoLabel.classList.add("auto-active");

  await loadWordlists();

  initSevFilters("sev-filter-bar", (sev) => {
    _sevFilter = sev;
    renderFindings(_allFindings);
  });

  document.getElementById("btn-launch").onclick = launchScan;
  document.getElementById("btn-kill").onclick   = killScan;
  document.getElementById("btn-reset").onclick  = resetUI;

  document.getElementById("btn-dl-json").onclick = () =>
    _scanId && window.open(`/api/report/${_scanId}/json`, "_blank");
  document.getElementById("btn-dl-pdf").onclick  = () =>
    _scanId && window.open(`/api/report/${_scanId}/pdf`,  "_blank");

  refreshHeaderStats();
  setInterval(refreshHeaderStats, 30000);
}

async function refreshHeaderStats() {
  try {
    const r = await fetch("/api/stats");
    const s = await r.json();
    const el = document.getElementById("header-stat");
    if (el) el.textContent =
      `${s.total_scans} scans · ${s.total_findings || 0} findings · ${s.active_scans} active`;
  } catch { /* silent */ }
}

// ── WORDLISTS ──────────────────────────────────────────────────────────────

async function loadWordlists() {
  try {
    const r    = await fetch("/api/wordlists");
    const list = await r.json();
    const sel  = document.getElementById("f-wordlist");
    list.forEach(w => {
      const o = document.createElement("option");
      o.value = `wordlists/${w}`;
      o.textContent = w;
      sel.appendChild(o);
    });
  } catch { /* silent */ }
}

// ── CHECKBOXES ─────────────────────────────────────────────────────────────
// Called after every renderTests() to re-bind the new DOM elements

function initCheckboxes() {
  // After renderTests() rewrites the DOM, we query fresh references each time.
  // We use event delegation on the grid so no stale closures survive re-renders.

  const grid = document.getElementById("tests-grid");
  if (!grid) return;

  // Remove any previous delegated listener by replacing the node's handler
  // via a named function stored on the element itself.
  if (grid._checkDelegate) {
    grid.removeEventListener("change", grid._checkDelegate);
  }

  grid._checkDelegate = function(e) {
    const chkAll   = document.getElementById("chk-all");
    const testChks = [...document.querySelectorAll(".test-chk")];

    if (e.target.id === "chk-all") {
      // ALL toggled
      if (chkAll.checked) {
        // ALL on → disable + uncheck individual tests
        testChks.forEach(c => { c.disabled = true; c.checked = false; });
        testChks.forEach(c => c.closest(".check-opt").classList.remove("check-opt--active"));
      } else {
        // ALL off → enable individual tests so user can pick
        testChks.forEach(c => { c.disabled = false; });
      }
    } else if (e.target.classList.contains("test-chk")) {
      // Individual test toggled — make sure ALL is unchecked
      const chkAll = document.getElementById("chk-all");
      if (chkAll) chkAll.checked = false;
    }
  };

  grid.addEventListener("change", grid._checkDelegate);

  // Initial state: ALL checked → individual tests disabled
  const chkAll   = document.getElementById("chk-all");
  const testChks = [...document.querySelectorAll(".test-chk")];
  if (chkAll && chkAll.checked) {
    testChks.forEach(c => { c.disabled = true; c.checked = false; });
  } else if (chkAll) {
    testChks.forEach(c => { c.disabled = false; });
  }
}

// ── GET FORM DATA ──────────────────────────────────────────────────────────

function getFormData() {
  const chkAll  = document.getElementById("chk-all");
  const tests   = chkAll?.checked
    ? ["all"]
    : [...document.querySelectorAll(".test-chk:checked")].map(c => c.value);

  const apiType  = document.querySelector("input[name=api_type]:checked")?.value || "AUTO";
  const discMode = document.querySelector("input[name=disc_mode]:checked")?.value  || "quick";

  return {
    url:          document.getElementById("f-url").value.trim(),
    endpoint:     document.getElementById("f-endpoint").value.trim(),
    api_type:     apiType,   // "AUTO" = let discovery decide, or "REST"/"GRAPHQL"/"SOAP"
    disc_mode:    discMode,  // "quick" (50 paths) or "full" (entire wordlist)
    tests:        tests.length ? tests : ["all"],
    wordlist:     document.getElementById("f-wordlist")?.value.trim() || "",
    token:        document.getElementById("f-token").value.trim(),
    second_token: document.getElementById("f-second-token")?.value.trim() || "",
    cookie:       document.getElementById("f-cookie").value.trim(),
    api_key:      document.getElementById("f-apikey").value.trim(),
    api_key_name: document.getElementById("f-apikey-name")?.value.trim() || "",
    login_url:    document.getElementById("f-login-url")?.value.trim() || "",
    username:     document.getElementById("f-username")?.value.trim() || "",
    password:     document.getElementById("f-password")?.value.trim() || "",
    timeout:      parseInt(document.getElementById("f-timeout")?.value || "10", 10),
    verbose:      document.getElementById("f-verbose").checked,
    deep:         document.getElementById("f-deep").checked,
  };
}

// ── LAUNCH ────────────────────────────────────────────────────────────────

async function launchScan() {
  const data = getFormData();

  if (!data.url) { shake("f-url"); return; }
  if (!data.url.startsWith("http://") && !data.url.startsWith("https://")) {
    shake("f-url");
    notify("Invalid URL — must start with http:// or https://", "error");
    return;
  }
  // If api_type is forced (not AUTO) and no endpoint → full scan with forced type
  // If endpoint provided → single endpoint scan

  // Reset state
  _allFindings = []; _sevFilter = "all";
  clearLog(); hidePanels();
  setScanStatus("running", "RUNNING");
  setButtons("scanning");
  startTimer();

  show("output-panel");
  show("findings-panel");

  try {
    const resp    = await fetch("/api/scan", {
      method:  "POST",
      headers: { "Content-Type": "application/json" },
      body:    JSON.stringify(data),
    });
    const payload = await resp.json();
    if (!resp.ok) throw new Error(payload.error || "Server error");

    _scanId = payload.scan_id;
    openSSE(_scanId);
  } catch (err) {
    appendLog({ text: `❌ ${err.message}`, cls: "error" });
    setScanStatus("error", "ERROR");
    setButtons("idle");
    stopTimer();
  }
}

// ── KILL ──────────────────────────────────────────────────────────────────

async function killScan() {
  if (!_scanId) return;
  try {
    await fetch(`/api/scan/${_scanId}/kill`, { method: "POST" });
    appendLog({ text: "⏹  Stop signal sent…", cls: "warn" });
  } catch { /* silent */ }
}

// ── RESET ─────────────────────────────────────────────────────────────────

function resetUI() {
  if (_evtSource) { _evtSource.close(); _evtSource = null; }
  stopTimer();
  _scanId = null; _allFindings = [];
  clearLog(); hidePanels();
  setScanStatus("ready", "READY");
  setButtons("idle");
}

// ── SSE ───────────────────────────────────────────────────────────────────

function openSSE(scanId) {
  if (_evtSource) _evtSource.close();
  _evtSource = new EventSource(`/api/stream/${scanId}`);

  _evtSource.onmessage = (e) => handleSSEMsg(JSON.parse(e.data));

  _evtSource.onerror = () => {
    appendLog({ text: "⚠  SSE connection lost.", cls: "warn" });
    _evtSource.close();
    setButtons("idle");
    stopTimer();
  };
}

function handleSSEMsg(msg) {
  switch (msg.type) {
    case "log":
      appendLog(msg);
      break;
    case "results":
      _allFindings = Array.isArray(msg.data) ? msg.data : [];
      break;
    case "done":
      stopTimer(); _evtSource?.close();
      setScanStatus("done", "DONE");
      setButtons("idle");
      updateStatCards(msg.stats);
      updateSevBtnCounts(msg.stats);
      renderFindings(_allFindings);
      show("export-row"); show("stats-bar");
      break;
    case "killed":
      stopTimer(); _evtSource?.close();
      setScanStatus("killed", "STOPPED");
      setButtons("idle");
      break;
    case "error":
      appendLog({ text: msg.text || "Unknown error", cls: "error" });
      setScanStatus("error", "ERROR");
      setButtons("idle"); stopTimer();
      break;
    case "end": _evtSource?.close(); break;
    case "ping": break;
  }
}

// ── LOG CONSOLE ────────────────────────────────────────────────────────────

function appendLog(msg) {
  const inner = document.getElementById("log-inner");
  if (!inner) return;
  const el = document.createElement("div");
  el.className = `log-line ${msg.cls || "default"}`;

  const now = new Date();
  const ts  = [now.getHours(), now.getMinutes(), now.getSeconds()]
    .map(n => String(n).padStart(2,"0")).join(":");

  el.innerHTML = `<span class="log-ts">${ts}</span><span class="log-text">${esc(msg.text || "")}</span>`;
  inner.appendChild(el);

  if (document.getElementById("chk-autoscroll")?.checked !== false) {
    document.getElementById("log-console").scrollTop = 999999;
  }
}

function clearLog() {
  const inner = document.getElementById("log-inner");
  if (inner) inner.innerHTML = "";
}

// ── FINDINGS ──────────────────────────────────────────────────────────────

function renderFindings(findings) {
  const list  = document.getElementById("findings-list");
  const empty = document.getElementById("no-findings");
  if (!list) return;

  const filtered = _sevFilter === "all"
    ? findings
    : findings.filter(f => (f.severity || "INFO").toUpperCase() === _sevFilter);

  if (!findings.length) {
    list.innerHTML = "";
    empty.innerHTML = `<div class="empty-state">
      <div class="empty-icon" style="font-size:2rem;opacity:.3">✓</div>
      <div class="empty-title">No vulnerabilities detected</div></div>`;
    return;
  }

  empty.innerHTML = "";
  list.innerHTML = filtered.length
    ? filtered.map(buildFindingCard).join("")
    : `<div class="empty-state">
        <div class="empty-icon">🔍</div>
        <div class="empty-title">No findings for this filter</div>
       </div>`;
}

// ── STAT CARDS ─────────────────────────────────────────────────────────────

function updateStatCards(stats) {
  SEV_ORDER.forEach(s => {
    const el = document.getElementById(`cnt-${s.toLowerCase()}`);
    if (el) animateNumber(el, stats[s] || 0);
  });
  const tot = document.getElementById("cnt-total");
  if (tot) animateNumber(tot, stats.total || 0);
  const dur = document.getElementById("cnt-duration");
  if (dur) dur.textContent = fmtDur(stats.duration);
}

function animateNumber(el, target) {
  const start = parseInt(el.textContent) || 0;
  const steps = 20;
  let   i     = 0;
  const inc   = (target - start) / steps;
  const iv    = setInterval(() => {
    i++;
    el.textContent = i >= steps ? target : Math.round(start + inc * i);
    if (i >= steps) clearInterval(iv);
  }, 30);
}

function updateSevBtnCounts(stats) {
  document.querySelectorAll(".sev-filter-bar .sev-btn").forEach(btn => {
    const badge = btn.querySelector(".sev-count");
    if (!badge) return;
    const sev = btn.dataset.sev;
    badge.textContent = sev === "all" ? (stats.total || 0) : (stats[sev] || 0);
  });
}

// ── SEVERITY FILTER BAR ────────────────────────────────────────────────────

function initSevFilters(containerId, onFilter) {
  const container = document.getElementById(containerId);
  if (!container) return;
  container.querySelectorAll(".sev-btn").forEach(btn => {
    btn.onclick = () => {
      container.querySelectorAll(".sev-btn").forEach(b => b.classList.remove("active"));
      btn.classList.add("active");
      onFilter(btn.dataset.sev);
    };
  });
}

// ── UI STATE ──────────────────────────────────────────────────────────────

function setScanStatus(cls, text) {
  const el = document.getElementById("scan-status-badge");
  if (!el) return;
  el.className   = `status-badge ${cls}`;
  el.textContent = text;
}

function setButtons(state) {
  const btnLaunch = document.getElementById("btn-launch");
  const btnKill   = document.getElementById("btn-kill");
  if (!btnLaunch || !btnKill) return;
  btnLaunch.style.display = state === "scanning" ? "none"        : "inline-flex";
  btnKill.style.display   = state === "scanning" ? "inline-flex" : "none";
}

function hidePanels() {
  hide("stats-bar"); hide("export-row");
  const fl = document.getElementById("findings-list");
  if (fl) fl.innerHTML = "";
  const nf = document.getElementById("no-findings");
  if (nf) nf.innerHTML = `<div class="empty-state">
    <div class="empty-icon" style="font-size:2rem;opacity:.3">◎</div>
    <div class="empty-title">Waiting for scan…</div></div>`;
}

function show(id) { document.getElementById(id)?.classList.remove("hidden"); }
function hide(id) { document.getElementById(id)?.classList.add("hidden"); }

function shake(id) {
  const el = document.getElementById(id);
  if (!el) return;
  el.classList.add("shake");
  setTimeout(() => el.classList.remove("shake"), 400);
  el.focus();
}

// ── TIMER ─────────────────────────────────────────────────────────────────

function startTimer() {
  _timerSecs = 0; stopTimer(); tickTimer();
  _timerHandle = setInterval(tickTimer, 1000);
}

function stopTimer() {
  if (_timerHandle) { clearInterval(_timerHandle); _timerHandle = null; }
}

function tickTimer() {
  const el = document.getElementById("scan-timer");
  if (!el) return;
  const m = String(Math.floor(_timerSecs / 60)).padStart(2, "0");
  const s = String(_timerSecs % 60).padStart(2, "0");
  el.textContent = `${m}:${s}`;
  _timerSecs++;
}

// ═══════════════════════════════════════════════════════════════════════════
// ═══════════════════════════════════════════════════════════════════════════
// HISTORY PAGE
// ═══════════════════════════════════════════════════════════════════════════
// ═══════════════════════════════════════════════════════════════════════════

let _historyScans    = [];
let _detailFindings  = [];
let _detailScanId    = null;
let _detailSevFilter = "all";

function isHistoryPage() { return !!document.getElementById("history-body"); }

async function initHistoryPage() {
  await loadHistory();
  initSevFilters("detail-sev-filters", (sev) => {
    _detailSevFilter = sev;
    renderDetailFindings();
  });

  document.getElementById("btn-refresh").onclick   = loadHistory;
  document.getElementById("btn-clear-all").onclick = clearAllScans;
  document.getElementById("detail-close").onclick  = closeDetail;
  document.getElementById("detail-dl-json").onclick = () =>
    _detailScanId && window.open(`/api/report/${_detailScanId}/json`, "_blank");
  document.getElementById("detail-dl-pdf").onclick  = () =>
    _detailScanId && window.open(`/api/report/${_detailScanId}/pdf`,  "_blank");
}

async function loadHistory() {
  const tbody = document.getElementById("history-body");
  tbody.innerHTML = `<tr class="loading-row"><td colspan="8">Loading…</td></tr>`;
  try {
    const r = await fetch("/api/scans?limit=100");
    const d = await r.json();
    _historyScans = d.scans || [];
    renderHistoryTable(_historyScans);
    renderHistoryKPIs(_historyScans);
    show("history-kpis");
  } catch {
    tbody.innerHTML = `<tr class="loading-row"><td colspan="8">Failed to load history</td></tr>`;
  }
}

function renderHistoryKPIs(scans) {
  if (!scans.length) { hide("history-kpis"); return; }
  set("kpi-scans",    scans.length);
  set("kpi-findings", scans.reduce((a,s) => a + (s.findings||0), 0));
  set("kpi-critical", scans.reduce((a,s) => a + (s.critical||0), 0));
  set("kpi-targets",  new Set(scans.map(s => s.target)).size);
  set("kpi-done",     scans.filter(s => s.status === "done").length);
}

function set(id, val) { const el = document.getElementById(id); if (el) el.textContent = val; }

function renderHistoryTable(scans) {
  const tbody = document.getElementById("history-body");
  if (!scans.length) {
    tbody.innerHTML = `<tr class="loading-row"><td colspan="8">No scans recorded yet</td></tr>`;
    return;
  }

  tbody.innerHTML = scans.map(s => {
    const sevParts = [
      s.critical ? `<span class="sm-c">${s.critical}C</span>` : "",
      s.high     ? `<span class="sm-h">${s.high}H</span>`     : "",
      s.medium   ? `<span class="sm-m">${s.medium}M</span>`   : "",
      s.low      ? `<span class="sm-l">${s.low}L</span>`      : "",
    ].filter(Boolean).join(" ");

    return `
    <tr>
      <td class="mono muted" style="font-size:.68rem;white-space:nowrap">${fmtDate(s.created_at)}</td>
      <td class="ht-target" title="${esc(s.target)}">${esc(s.target)}</td>
      <td><span class="api-tag ${esc(s.api_type)}">${esc(s.api_type)}</span></td>
      <td class="muted" style="font-size:.7rem;max-width:120px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap">${esc(s.tests)}</td>
      <td><span class="scan-status ${s.status}">${s.status.toUpperCase()}</span></td>
      <td><div class="sev-mini">${sevParts || '<span class="muted">—</span>'}</div></td>
      <td class="mono muted" style="font-size:.7rem">${fmtDur(s.duration_sec)}</td>
      <td>
        <div class="action-btns">
          <button class="icon-btn" onclick="openDetail('${s.id}')">👁 View</button>
          <button class="icon-btn" onclick="dlJson('${s.id}')">JSON</button>
          <button class="icon-btn" onclick="dlPdf('${s.id}')">PDF</button>
          <button class="icon-btn danger" onclick="deleteScan('${s.id}')">✕</button>
        </div>
      </td>
    </tr>`;
  }).join("");
}

async function openDetail(scanId) {
  _detailScanId    = scanId;
  _detailSevFilter = "all";
  document.querySelectorAll("#detail-sev-filters .sev-btn").forEach((b, i) => {
    b.classList.toggle("active", i === 0);
  });
  show("detail-panel");

  try {
    const r    = await fetch(`/api/scans/${scanId}`);
    const data = await r.json();
    const scan = data.scan;
    _detailFindings = data.findings || [];

    ["critical","high","medium","low","info"].forEach(s => {
      const el = document.getElementById(`d-cnt-${s}`);
      if (el) el.textContent = scan[s] || 0;
    });

    renderDetailFindings();
    document.getElementById("detail-panel").scrollIntoView({ behavior:"smooth", block:"start" });
  } catch { notify("Failed to load scan details", "error"); }
}

function renderDetailFindings() {
  const list = document.getElementById("detail-findings");
  if (!list) return;
  const filtered = _detailSevFilter === "all"
    ? _detailFindings
    : _detailFindings.filter(f => (f.severity||"INFO").toUpperCase() === _detailSevFilter);
  list.innerHTML = filtered.length
    ? filtered.map(buildFindingCard).join("")
    : `<div class="empty-state"><div class="empty-icon">🔍</div>
       <div class="empty-title">No findings for this filter</div></div>`;
}

function closeDetail() { hide("detail-panel"); _detailScanId = null; _detailFindings = []; }

async function deleteScan(scanId) {
  if (!confirm("Delete this scan and all its findings?")) return;
  const r = await fetch(`/api/scans/${scanId}`, { method: "DELETE" });
  if (r.ok) { notify("Scan deleted", "success"); if (_detailScanId === scanId) closeDetail(); await loadHistory(); }
  else       { notify("Delete failed", "error"); }
}

async function clearAllScans() {
  if (!confirm("Delete ALL history? This action is irreversible.")) return;
  const r = await fetch("/api/scans", { method: "DELETE" });
  if (r.ok) { notify("History cleared", "success"); closeDetail(); await loadHistory(); }
}

function dlJson(id) { window.open(`/api/report/${id}/json`, "_blank"); }
function dlPdf(id)  { window.open(`/api/report/${id}/pdf`,  "_blank"); }

// ═══════════════════════════════════════════════════════════════════════════
// BOOT
// ═══════════════════════════════════════════════════════════════════════════

document.addEventListener("DOMContentLoaded", () => {
  initModal();
  injectNotifStyles();
  if (isIndexPage())   initIndexPage();
  if (isHistoryPage()) initHistoryPage();
});

// ── TOAST NOTIFICATIONS ────────────────────────────────────────────────────
function injectNotifStyles() {
  if (document.getElementById("notif-style")) return;
  const s = document.createElement("style");
  s.id = "notif-style";
  s.textContent = `
    .notif {
      position:fixed; bottom:1.5rem; right:1.5rem; z-index:9999;
      padding:.7rem 1.2rem; border-radius:4px; border:1px solid;
      font-family:'JetBrains Mono',monospace; font-size:.78rem;
      transform:translateX(120%); transition:transform .3s cubic-bezier(.16,1,.3,1);
      max-width:360px; word-break:break-word; backdrop-filter:blur(12px);
    }
    .notif.show { transform:none; }
    .notif-info    { background:rgba(0,229,255,.1); color:#00E5FF; border-color:rgba(0,229,255,.3); }
    .notif-success { background:rgba(0,230,118,.1); color:#00E676; border-color:rgba(0,230,118,.3); }
    .notif-error   { background:rgba(255,23,68,.1); color:#FF1744; border-color:rgba(255,23,68,.3); }
    .notif-warn    { background:rgba(255,214,0,.1); color:#FFD600; border-color:rgba(255,214,0,.3); }
  `;
  document.head.appendChild(s);
}