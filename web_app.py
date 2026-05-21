"""
APISec — Web Interface Backend
===============================
Flask server orchestrating CLI scans via subprocess,
streaming live logs via Server-Sent Events, persisting
results in SQLite, and generating JSON/PDF reports.

Architecture :
  Browser ←→ Flask (web_app.py) ←→ subprocess → main.py
                      ↕
                 SQLite (scans.db)

Author  : APISec PFE Team
Version : 2.1
"""

from __future__ import annotations

import contextlib
import io
import json
import logging
import os
import queue
import re
import signal
import sqlite3
import subprocess
import sys
import threading
import time
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Generator, Optional

from flask import (
    Flask,
    Response,
    g,
    jsonify,
    request,
    send_file,
    send_from_directory,
)

# ══════════════════════════════════════════════════════════════════════════════
# AI CONFIGURATION
# ══════════════════════════════════════════════════════════════════════════════

# Provider: "groq" | "claude" | "ollama"
# Set via environment variable:
#   export APISEC_AI_PROVIDER=groq    → Groq API (FREE — console.groq.com)
#   export APISEC_AI_PROVIDER=claude  → Claude API (paid — console.anthropic.com)
#   export APISEC_AI_PROVIDER=ollama  → Local Ollama (free, no internet needed)
#
# Groq setup (recommended — free):
#   1. Go to console.groq.com → Create free account → API Keys → Create
#   2. export GROQ_API_KEY=gsk_...
#   3. python web_app.py
AI_PROVIDER     = os.getenv("APISEC_AI_PROVIDER", "groq").lower()
GROQ_API_KEY    = os.getenv("GROQ_API_KEY", "")
GROQ_MODEL      = os.getenv("GROQ_MODEL", "llama-3.1-8b-instant")  # most stable free model

ANTHROPIC_KEY   = os.getenv("ANTHROPIC_API_KEY", "")
OLLAMA_URL      = os.getenv("OLLAMA_URL", "http://localhost:11434")
OLLAMA_MODEL    = os.getenv("OLLAMA_MODEL", "llama3.2")
CLAUDE_MODEL    = "claude-sonnet-4-5"

AI_SYSTEM_PROMPT = """You are APISec AI, an expert API security assistant embedded in the APISec audit tool.
You help security analysts understand vulnerabilities, explain attack scenarios, suggest fixes, and generate reports.

When analyzing findings:
- Be precise and technical but clear
- Always mention OWASP API Security Top 10 references
- Suggest concrete remediation steps
- Highlight attack chains when multiple findings are related
- Assess the overall risk level

Keep responses concise but complete. Use markdown formatting for readability."""

# ══════════════════════════════════════════════════════════════════════════════
# CONFIGURATION
# ══════════════════════════════════════════════════════════════════════════════

BASE_DIR = Path(__file__).parent.resolve()
WEB_DIR  = BASE_DIR / "web"
DB_PATH  = BASE_DIR / "scans.db"
REPORTS  = BASE_DIR / "reports"
LOGS_DIR = BASE_DIR / "logs"

REPORTS.mkdir(exist_ok=True)
LOGS_DIR.mkdir(exist_ok=True)

# ── Load .env automatically ────────────────────────────────────────────────
def _load_dotenv() -> None:
    """
    Load KEY=VALUE pairs from .env at project root.
    Pure stdlib — no external dependency.
    Variables already set in the environment take priority.
    """
    env_path = BASE_DIR / ".env"
    if not env_path.exists():
        return
    with open(env_path, encoding="utf-8") as fh:
        for line in fh:
            line = line.strip()
            if not line or line.startswith("#") or "=" not in line:
                continue
            key, _, value = line.partition("=")
            key   = key.strip()
            value = value.strip().strip('"').strip("'")
            if key and key not in os.environ:
                os.environ[key] = value

_load_dotenv()  # runs before AI config reads os.environ

SEV_ORDER   = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]
SEV_WEIGHTS = {s: i for i, s in enumerate(SEV_ORDER)}

# ══════════════════════════════════════════════════════════════════════════════
# FLASK APP
# ══════════════════════════════════════════════════════════════════════════════

app = Flask(__name__, static_folder=str(WEB_DIR / "static"))
app.config["SECRET_KEY"] = os.urandom(32)
app.config["JSON_SORT_KEYS"] = False

logging.getLogger("werkzeug").setLevel(logging.WARNING)

_log_handler = logging.FileHandler(LOGS_DIR / "web_app.log")
_log_handler.setFormatter(logging.Formatter(
    "%(asctime)s [%(levelname)s] %(message)s", datefmt="%Y-%m-%d %H:%M:%S"
))
app.logger.addHandler(_log_handler)
app.logger.setLevel(logging.INFO)


# ══════════════════════════════════════════════════════════════════════════════
# ACTIVE SCAN REGISTRY
# ══════════════════════════════════════════════════════════════════════════════

class ScanRegistry:
    def __init__(self) -> None:
        self._lock:      threading.Lock                         = threading.Lock()
        self._queues:    dict[str, queue.Queue]                 = {}
        self._processes: dict[str, Optional[subprocess.Popen]] = {}

    def register(self, scan_id: str) -> queue.Queue:
        q: queue.Queue = queue.Queue(maxsize=2000)
        with self._lock:
            self._queues[scan_id]    = q
            self._processes[scan_id] = None
        return q

    def attach_process(self, scan_id: str, proc: subprocess.Popen) -> None:
        with self._lock:
            self._processes[scan_id] = proc

    def get_queue(self, scan_id: str) -> Optional[queue.Queue]:
        with self._lock:
            return self._queues.get(scan_id)

    def kill(self, scan_id: str) -> bool:
        with self._lock:
            proc = self._processes.get(scan_id)
        if proc and proc.poll() is None:
            try:
                proc.send_signal(signal.SIGTERM)
                proc.wait(timeout=3)
            except Exception:
                with contextlib.suppress(Exception):
                    proc.kill()
            return True
        return False

    def unregister(self, scan_id: str) -> None:
        with self._lock:
            self._queues.pop(scan_id, None)
            self._processes.pop(scan_id, None)

    def active_ids(self) -> list[str]:
        with self._lock:
            return list(self._queues.keys())


_registry = ScanRegistry()


# ══════════════════════════════════════════════════════════════════════════════
# DATABASE
# ══════════════════════════════════════════════════════════════════════════════

SCHEMA = """
PRAGMA journal_mode = WAL;
PRAGMA foreign_keys = ON;

CREATE TABLE IF NOT EXISTS scans (
    id            TEXT PRIMARY KEY,
    created_at    TEXT NOT NULL,
    updated_at    TEXT NOT NULL,
    target        TEXT NOT NULL,
    api_type      TEXT NOT NULL DEFAULT 'REST',
    tests         TEXT NOT NULL DEFAULT 'all',
    mode          TEXT NOT NULL DEFAULT 'full',
    status        TEXT NOT NULL DEFAULT 'running'
        CHECK(status IN ('running','done','error','killed')),
    findings      INTEGER NOT NULL DEFAULT 0,
    critical      INTEGER NOT NULL DEFAULT 0,
    high          INTEGER NOT NULL DEFAULT 0,
    medium        INTEGER NOT NULL DEFAULT 0,
    low           INTEGER NOT NULL DEFAULT 0,
    info          INTEGER NOT NULL DEFAULT 0,
    duration_sec  REAL,
    results_json  TEXT,
    error_msg     TEXT
);

CREATE TABLE IF NOT EXISTS findings (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    scan_id       TEXT    NOT NULL REFERENCES scans(id) ON DELETE CASCADE,
    vuln_id       TEXT,
    vuln_type     TEXT,
    owasp         TEXT,
    cwe           TEXT,
    severity      TEXT    NOT NULL DEFAULT 'INFO'
        CHECK(severity IN ('CRITICAL','HIGH','MEDIUM','LOW','INFO')),
    confidence    TEXT    DEFAULT 'MEDIUM',
    endpoint      TEXT,
    method        TEXT,
    parameter     TEXT,
    payload       TEXT,
    evidence      TEXT,
    description   TEXT,
    solution      TEXT,
    reference     TEXT
);

CREATE INDEX IF NOT EXISTS idx_findings_scan   ON findings(scan_id);
CREATE INDEX IF NOT EXISTS idx_findings_sev    ON findings(severity);
CREATE INDEX IF NOT EXISTS idx_scans_created   ON scans(created_at DESC);
CREATE INDEX IF NOT EXISTS idx_scans_status    ON scans(status);
"""


def get_db() -> sqlite3.Connection:
    if "db" not in g:
        conn = sqlite3.connect(str(DB_PATH), check_same_thread=False)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA foreign_keys = ON")
        g.db = conn
    return g.db


@app.teardown_appcontext
def close_db(_exc: Any) -> None:
    db = g.pop("db", None)
    if db:
        db.close()


def init_db() -> None:
    with sqlite3.connect(str(DB_PATH)) as conn:
        conn.executescript(SCHEMA)
    app.logger.info("Database initialised at %s", DB_PATH)


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def _count_severities(findings: list[dict]) -> dict[str, int]:
    counts: dict[str, int] = {s: 0 for s in SEV_ORDER}
    for f in findings:
        sev = (f.get("severity") or "INFO").upper()
        counts[sev] = counts.get(sev, 0) + 1
    return counts


# ══════════════════════════════════════════════════════════════════════════════
# RESULT PARSER
# ══════════════════════════════════════════════════════════════════════════════

def _load_results(results_file: Path) -> list[dict]:
    if not results_file.exists():
        return []
    try:
        with open(results_file, encoding="utf-8") as fh:
            data = json.load(fh)
        if isinstance(data, list):
            return data
        if isinstance(data, dict) and "findings" in data:
            return data["findings"]
    except Exception as exc:
        app.logger.warning("Could not parse results file %s: %s", results_file, exc)
    return []


def _sort_findings(findings: list[dict]) -> list[dict]:
    return sorted(
        findings,
        key=lambda f: (
            SEV_WEIGHTS.get((f.get("severity") or "INFO").upper(), 99),
            f.get("endpoint") or "",
        ),
    )


# ══════════════════════════════════════════════════════════════════════════════
# SCAN RUNNER
# ══════════════════════════════════════════════════════════════════════════════

def _build_command(
    scan_id:      str,
    target:       str,
    endpoint:     str,
    api_type:     str,
    disc_mode:    str,
    tests:        str,
    wordlist:     str,
    token:        str,
    second_token: str,
    cookie:       str,
    api_key:      str,
    api_key_name: str,
    timeout:      int,
    login_url:    str,
    username:     str,
    password:     str,
    verbose:      bool,
    deep:         bool,
    results_file: Path,
) -> list[str]:
    """
    Build the main.py CLI command.
    Uses --output / --scan-output to write JSON results.
    Never modifies main.py.
    -X utf8 : forces UTF-8 on Windows (fixes cp1252 UnicodeEncodeError).
    """
    py  = sys.executable
    cmd = [py, "-X", "utf8", str(BASE_DIR / "main.py")]

    if endpoint.strip():
        # ── Single endpoint scan ─────────────────────────────────────────────
        path = endpoint.strip()
        if not path.startswith("/"):
            path = "/" + path
        sub_cmd = [
            "scan",
            "--url",      target,
            "--endpoint", path,
            "--tests",    tests,
            "--output",   str(results_file),
        ]
        # Force api_type only if user explicitly chose one (not AUTO)
        if api_type != "AUTO":
            sub_cmd += ["--api-type", api_type]
        cmd += sub_cmd
    else:
        # ── Full scan — discovery first, then scan ────────────────────────────
        # api_type AUTO → no --api-type flag → main.py discovery decides
        # api_type forced → pass --api-type to skip discovery detection
        wl = wordlist.strip() or str(BASE_DIR / "wordlists" / "api-endpoints-res.txt")
        sub_cmd = [
            "full",
            "--url",         target,
            "--wordlist",    wl,
            "--mode",        disc_mode,   # "quick" (50 paths) or "full" (all)
            "--tests",       tests,
            "--scan-output", str(results_file),
        ]
        cmd += sub_cmd

    # ── Authentication ──────────────────────────────────────────────────────
    if token:        cmd += ["--token",        token]
    if second_token: cmd += ["--second-token", second_token]
    if cookie:       cmd += ["--cookie",       cookie]
    if api_key:      cmd += ["--api-key",      api_key]
    if api_key_name: cmd += ["--api-key-name", api_key_name]

    # ── Auto-login ──────────────────────────────────────────────────────────
    if login_url: cmd += ["--login-url", login_url]
    if username:  cmd += ["--username",  username]
    if password:  cmd += ["--password",  password]

    # ── Options ─────────────────────────────────────────────────────────────
    if timeout and timeout != 10:
        cmd += ["--timeout", str(timeout)]
    if verbose: cmd.append("--verbose")
    if deep:    cmd.append("--deep")

    return cmd


def _strip_ansi(text: str) -> str:
    return re.sub(r"\x1b\[[0-9;]*[mGKH]", "", text)


def _classify_line(line: str) -> str:
    low = line.lower()
    if "critical" in low:                                          return "critical"
    if "[high]"   in low:                                          return "high"
    if "[medium]" in low:                                          return "medium"
    if "[low]"    in low:                                          return "low"
    if any(x in low for x in ("error", "❌", "[!]")):             return "error"
    if any(x in low for x in ("✓", "found", "detect", "✅", "[+]")): return "success"
    if any(x in low for x in ("warn", "[*]")):                    return "warn"
    return "default"


def _run_scan_thread(
    scan_id:      str,
    target:       str,
    endpoint:     str,
    api_type:     str,
    disc_mode:    str,
    tests:        str,
    wordlist:     str,
    token:        str,
    second_token: str,
    cookie:       str,
    api_key:      str,
    api_key_name: str,
    timeout:      int,
    login_url:    str,
    username:     str,
    password:     str,
    verbose:      bool,
    deep:         bool,
) -> None:
    q            = _registry.get_queue(scan_id)
    results_file = REPORTS / f"{scan_id}.json"
    t0           = time.monotonic()

    def push(msg_type: str, **kwargs: Any) -> None:
        with contextlib.suppress(queue.Full):
            q.put_nowait({"type": msg_type, **kwargs})

    def update_db(**fields: Any) -> None:
        with sqlite3.connect(str(DB_PATH)) as conn:
            sets = ", ".join(f"{k}=?" for k in fields)
            vals = list(fields.values()) + [scan_id]
            conn.execute(f"UPDATE scans SET {sets} WHERE id=?", vals)

    def insert_findings(findings: list[dict]) -> None:
        with sqlite3.connect(str(DB_PATH)) as conn:
            conn.executemany(
                """INSERT INTO findings
                   (scan_id, vuln_id, vuln_type, owasp, cwe, severity, confidence,
                    endpoint, method, parameter, payload, evidence, description,
                    solution, reference)
                   VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
                [
                    (
                        scan_id,
                        f.get("vuln_id"),    f.get("vuln_type"),
                        f.get("owasp"),      f.get("cwe"),
                        (f.get("severity") or "INFO").upper(),
                        f.get("confidence"),
                        f.get("endpoint"),   f.get("method"),
                        f.get("parameter"),  f.get("payload"),
                        f.get("evidence"),   f.get("description"),
                        f.get("solution"),   f.get("reference"),
                    )
                    for f in findings
                ],
            )

    cmd = _build_command(
        scan_id, target, endpoint, api_type, disc_mode, tests,
        wordlist, token, second_token, cookie,
        api_key, api_key_name, timeout,
        login_url, username, password,
        verbose, deep, results_file,
    )

    mode_label = "Full Scan (auto-discovery)" if api_type == "AUTO" else f"Single Endpoint [{api_type}]"
    push("log", text=f"▶  Scan ID : {scan_id}",    cls="info")
    push("log", text=f"▶  Target  : {target}",     cls="info")
    push("log", text=f"▶  Mode    : {mode_label}",  cls="info")
    push("log", text=f"▶  Tests   : {tests}",       cls="info")
    push("log", text=f"▶  Command : {' '.join(cmd)}", cls="dim")
    push("log", text="─" * 60, cls="dim")

    try:
        proc = subprocess.Popen(
            cmd,
            stdout   = subprocess.PIPE,
            stderr   = subprocess.STDOUT,
            text     = True,
            encoding = "utf-8",
            errors   = "replace",
            bufsize  = 1,
            cwd      = str(BASE_DIR),
            env      = {
                **os.environ,
                "PYTHONUNBUFFERED": "1",
                "PYTHONIOENCODING": "utf-8",
                "PYTHONUTF8":       "1",
            },
        )
        _registry.attach_process(scan_id, proc)

        for raw_line in proc.stdout:
            line = _strip_ansi(raw_line.rstrip())
            if not line:
                continue
            push("log", text=line, cls=_classify_line(line))

        proc.wait()
        duration = round(time.monotonic() - t0, 2)

        if proc.returncode == -15:
            update_db(status="killed", duration_sec=duration, updated_at=_now_iso())
            push("killed", duration=duration)
            push(None)
            return

        findings = _sort_findings(_load_results(results_file))
        counts   = _count_severities(findings)

        insert_findings(findings)
        update_db(
            status       = "done",
            updated_at   = _now_iso(),
            findings     = len(findings),
            critical     = counts["CRITICAL"],
            high         = counts["HIGH"],
            medium       = counts["MEDIUM"],
            low          = counts["LOW"],
            info         = counts["INFO"],
            duration_sec = duration,
            results_json = json.dumps(findings, ensure_ascii=False),
        )

        push("results", data=findings)
        push("done",
             stats={**counts, "total": len(findings), "duration": duration},
             scan_id=scan_id)
        push("log", text="─" * 60, cls="dim")
        push("log", text=f"✅  Scan done — {len(findings)} finding(s) in {duration}s",
             cls="success")

        app.logger.info("Scan %s done: %d findings in %.1fs", scan_id, len(findings), duration)

    except FileNotFoundError:
        msg = "❌  main.py not found — ensure web_app.py is at the project root."
        push("log", text=msg, cls="error")
        update_db(status="error", updated_at=_now_iso(), error_msg="main.py not found")
        app.logger.error("Scan %s: main.py not found", scan_id)

    except Exception as exc:
        msg = f"❌  Unexpected error: {exc}"
        push("log", text=msg, cls="error")
        update_db(status="error", updated_at=_now_iso(), error_msg=str(exc))
        app.logger.exception("Scan %s crashed", scan_id)

    finally:
        with contextlib.suppress(queue.Full):
            q.put_nowait(None)
        _registry.unregister(scan_id)


# ══════════════════════════════════════════════════════════════════════════════
# STATIC ROUTES
# ══════════════════════════════════════════════════════════════════════════════

@app.route("/")
def index() -> Response:
    return send_from_directory(str(WEB_DIR), "index.html")


@app.route("/history")
def history() -> Response:
    return send_from_directory(str(WEB_DIR), "history.html")


@app.route("/static/<path:filename>")
def static_files(filename: str) -> Response:
    return send_from_directory(str(WEB_DIR / "static"), filename)


# ══════════════════════════════════════════════════════════════════════════════
# API — SCAN MANAGEMENT
# ══════════════════════════════════════════════════════════════════════════════

@app.route("/api/scan", methods=["POST"])
def start_scan() -> tuple[Response, int]:
    """
    POST /api/scan
    Body (JSON): url, endpoint?, api_type, tests[], wordlist?,
                 token?, second_token?, cookie?, api_key?, api_key_name?,
                 timeout?, login_url?, username?, password?,
                 verbose, deep
    """
    data = request.get_json(force=True, silent=True) or {}

    target       = (data.get("url")          or "").strip()
    endpoint     = (data.get("endpoint")     or "").strip()
    api_type     = (data.get("api_type")     or "AUTO").upper()
    disc_mode    = (data.get("disc_mode")    or "quick").lower()
    tests_l      = data.get("tests")         or ["all"]
    wordlist     = (data.get("wordlist")     or "").strip()
    token        = (data.get("token")        or "").strip()
    second_token = (data.get("second_token") or "").strip()
    cookie       = (data.get("cookie")       or "").strip()
    api_key      = (data.get("api_key")      or "").strip()
    api_key_name = (data.get("api_key_name") or "").strip()
    login_url    = (data.get("login_url")    or "").strip()
    username     = (data.get("username")     or "").strip()
    password     = (data.get("password")     or "").strip()
    timeout      = int(data.get("timeout",  10))
    verbose      = bool(data.get("verbose", False))
    deep         = bool(data.get("deep",    False))

    if not target:
        return jsonify({"error": "Target URL is required"}), 400
    if not target.startswith(("http://", "https://")):
        return jsonify({"error": "Invalid URL — must start with http:// or https://"}), 400

    # Validate api_type — AUTO means discovery decides
    if api_type not in ("REST", "GRAPHQL", "SOAP", "AUTO"):
        api_type = "AUTO"
    if disc_mode not in ("quick", "full"):
        disc_mode = "quick"
    if not 1 <= timeout <= 60:
        timeout = 10

    tests_str = ",".join(tests_l) if isinstance(tests_l, list) else str(tests_l)
    scan_id   = str(uuid.uuid4())
    now       = _now_iso()

    db = get_db()
    db.execute(
        """INSERT INTO scans
           (id, created_at, updated_at, target, api_type, tests, status)
           VALUES (?,?,?,?,?,?,?)""",
        (scan_id, now, now, target, api_type, tests_str, "running"),
    )
    db.commit()

    _registry.register(scan_id)

    t = threading.Thread(
        target = _run_scan_thread,
        args   = (
            scan_id, target, endpoint, api_type, disc_mode, tests_str,
            wordlist, token, second_token, cookie,
            api_key, api_key_name, timeout,
            login_url, username, password,
            verbose, deep,
        ),
        daemon = True,
        name   = f"scan-{scan_id[:8]}",
    )
    t.start()

    app.logger.info("Scan %s started: %s  tests=%s", scan_id, target, tests_str)
    return jsonify({"scan_id": scan_id}), 202


@app.route("/api/scan/<scan_id>/kill", methods=["POST"])
def kill_scan(scan_id: str) -> tuple[Response, int]:
    killed = _registry.kill(scan_id)
    if not killed:
        return jsonify({"error": "Scan not found or already finished"}), 404
    return jsonify({"ok": True, "scan_id": scan_id})


# ══════════════════════════════════════════════════════════════════════════════
# API — SERVER-SENT EVENTS
# ══════════════════════════════════════════════════════════════════════════════

@app.route("/api/stream/<scan_id>")
def stream(scan_id: str) -> Response:
    def generate() -> Generator[str, None, None]:
        q: Optional[queue.Queue] = None
        for _ in range(80):
            q = _registry.get_queue(scan_id)
            if q is not None:
                break
            time.sleep(0.1)

        if q is None:
            yield f"data: {json.dumps({'type':'error','text':'Scan not found'})}\n\n"
            return

        while True:
            try:
                item = q.get(timeout=20)
            except queue.Empty:
                yield f"data: {json.dumps({'type':'ping'})}\n\n"
                continue

            if item is None:
                yield f"data: {json.dumps({'type':'end'})}\n\n"
                break

            yield f"data: {json.dumps(item, ensure_ascii=False)}\n\n"

    return Response(
        generate(),
        mimetype = "text/event-stream",
        headers  = {
            "Cache-Control":     "no-cache",
            "X-Accel-Buffering": "no",
            "Connection":        "keep-alive",
        },
    )


# ══════════════════════════════════════════════════════════════════════════════
# API — HISTORY / CRUD
# ══════════════════════════════════════════════════════════════════════════════

@app.route("/api/scans")
def list_scans() -> Response:
    page     = max(1, int(request.args.get("page",  1)))
    limit    = min(200, max(1, int(request.args.get("limit", 50))))
    status   = request.args.get("status",   "").strip()
    severity = request.args.get("severity", "").strip().upper()

    where, params = [], []
    if status:
        where.append("status = ?")
        params.append(status)
    if severity in SEV_ORDER:
        where.append(f"{severity.lower()} > 0")

    where_sql = ("WHERE " + " AND ".join(where)) if where else ""
    offset    = (page - 1) * limit

    db    = get_db()
    total = db.execute(f"SELECT COUNT(*) FROM scans {where_sql}", params).fetchone()[0]
    rows  = db.execute(
        f"SELECT * FROM scans {where_sql} ORDER BY created_at DESC LIMIT ? OFFSET ?",
        params + [limit, offset],
    ).fetchall()

    return jsonify({"total": total, "page": page, "limit": limit,
                    "scans": [dict(r) for r in rows]})


@app.route("/api/scans/<scan_id>")
def get_scan(scan_id: str) -> tuple[Response, int]:
    db   = get_db()
    scan = db.execute("SELECT * FROM scans WHERE id=?", (scan_id,)).fetchone()
    if not scan:
        return jsonify({"error": "Scan not found"}), 404

    findings = db.execute(
        """SELECT * FROM findings WHERE scan_id=?
           ORDER BY CASE severity
             WHEN 'CRITICAL' THEN 0 WHEN 'HIGH' THEN 1 WHEN 'MEDIUM' THEN 2
             WHEN 'LOW' THEN 3 ELSE 4 END, endpoint""",
        (scan_id,),
    ).fetchall()

    return jsonify({"scan": dict(scan), "findings": [dict(f) for f in findings]})


@app.route("/api/scans/<scan_id>", methods=["DELETE"])
def delete_scan(scan_id: str) -> tuple[Response, int]:
    db = get_db()
    if not db.execute("SELECT id FROM scans WHERE id=?", (scan_id,)).fetchone():
        return jsonify({"error": "Scan not found"}), 404
    db.execute("DELETE FROM scans WHERE id=?", (scan_id,))
    db.commit()
    with contextlib.suppress(FileNotFoundError):
        (REPORTS / f"{scan_id}.json").unlink()
    return jsonify({"ok": True})


@app.route("/api/scans", methods=["DELETE"])
def delete_all_scans() -> Response:
    db = get_db()
    db.execute("DELETE FROM scans")
    db.commit()
    for f in REPORTS.glob("*.json"):
        with contextlib.suppress(Exception):
            f.unlink()
    return jsonify({"ok": True})


@app.route("/api/stats")
def global_stats() -> Response:
    db  = get_db()
    row = db.execute("""
        SELECT
            COUNT(*)                          AS total_scans,
            SUM(findings)                     AS total_findings,
            SUM(critical)                     AS total_critical,
            SUM(high)                         AS total_high,
            SUM(medium)                       AS total_medium,
            SUM(low)                          AS total_low,
            SUM(info)                         AS total_info,
            COUNT(DISTINCT target)            AS unique_targets,
            AVG(duration_sec)                 AS avg_duration,
            SUM(CASE WHEN status='done'    THEN 1 ELSE 0 END) AS done_count,
            SUM(CASE WHEN status='error'   THEN 1 ELSE 0 END) AS error_count,
            SUM(CASE WHEN status='running' THEN 1 ELSE 0 END) AS running_count
        FROM scans
    """).fetchone()
    return jsonify({**dict(row), "active_scans": len(_registry.active_ids())})


# ══════════════════════════════════════════════════════════════════════════════
# API — REPORTS
# ══════════════════════════════════════════════════════════════════════════════

@app.route("/api/report/<scan_id>/json")
def report_json(scan_id: str) -> tuple[Response, int]:
    db   = get_db()
    scan = db.execute("SELECT * FROM scans WHERE id=?", (scan_id,)).fetchone()
    if not scan:
        return jsonify({"error": "Scan not found"}), 404

    payload = {
        "meta": {
            "tool":       "APISec v2.1",
            "scan_id":    scan_id,
            "target":     scan["target"],
            "api_type":   scan["api_type"],
            "tests":      scan["tests"],
            "status":     scan["status"],
            "created_at": scan["created_at"],
            "duration_s": scan["duration_sec"],
            "findings":   scan["findings"],
        },
        "summary": {
            "CRITICAL": scan["critical"],
            "HIGH":     scan["high"],
            "MEDIUM":   scan["medium"],
            "LOW":      scan["low"],
            "INFO":     scan["info"],
        },
        "findings": json.loads(scan["results_json"] or "[]"),
    }

    buf = io.BytesIO(json.dumps(payload, indent=2, ensure_ascii=False).encode("utf-8"))
    buf.seek(0)
    fname = f"apisec_report_{scan_id[:8]}_{datetime.now().strftime('%Y%m%d')}.json"
    return send_file(buf, mimetype="application/json",
                     as_attachment=True, download_name=fname)


@app.route("/api/report/<scan_id>/pdf")
def report_pdf(scan_id: str) -> tuple[Response, int]:
    try:
        from reportlab.lib           import colors
        from reportlab.lib.pagesizes import A4
        from reportlab.lib.styles    import ParagraphStyle
        from reportlab.lib.units     import cm, mm
        from reportlab.platypus      import (
            HRFlowable, PageBreak, Paragraph,
            SimpleDocTemplate, Spacer, Table, TableStyle,
        )
    except ImportError:
        return jsonify({"error": "reportlab not installed",
                        "fix":   "pip install reportlab"}), 500

    db   = get_db()
    scan = db.execute("SELECT * FROM scans WHERE id=?", (scan_id,)).fetchone()
    if not scan:
        return jsonify({"error": "Scan not found"}), 404

    findings_rows = db.execute(
        """SELECT * FROM findings WHERE scan_id=?
           ORDER BY CASE severity
             WHEN 'CRITICAL' THEN 0 WHEN 'HIGH' THEN 1 WHEN 'MEDIUM' THEN 2
             WHEN 'LOW' THEN 3 ELSE 4 END""",
        (scan_id,),
    ).fetchall()

    C = {
        "bg":       colors.HexColor("#060810"),
        "surface":  colors.HexColor("#0d1117"),
        "accent":   colors.HexColor("#00E5FF"),
        "text":     colors.HexColor("#C9D1E0"),
        "dim":      colors.HexColor("#4A5568"),
        "CRITICAL": colors.HexColor("#FF2D55"),
        "HIGH":     colors.HexColor("#FF6B35"),
        "MEDIUM":   colors.HexColor("#FFB800"),
        "LOW":      colors.HexColor("#00D9A3"),
        "INFO":     colors.HexColor("#4A9EFF"),
        "white":    colors.white,
        "black":    colors.black,
    }

    buf = io.BytesIO()
    doc = SimpleDocTemplate(
        buf, pagesize=A4,
        leftMargin=2*cm, rightMargin=2*cm,
        topMargin=2.5*cm, bottomMargin=2*cm,
        title=f"APISec Security Report — {scan['target']}",
        author="APISec v2.1",
    )

    # Unique style names per scan to avoid reportlab global registry conflicts
    _uid = scan_id[:8]
    _ctr = [0]

    def S(name, **kw) -> ParagraphStyle:
        _ctr[0] += 1
        return ParagraphStyle(f"{name}_{_uid}_{_ctr[0]}", **kw)

    style_h1    = S("h1",   fontSize=22, fontName="Helvetica-Bold", textColor=C["accent"], spaceAfter=4)
    style_h2    = S("h2",   fontSize=13, fontName="Helvetica-Bold", textColor=C["text"],   spaceBefore=12, spaceAfter=6)
    style_body  = S("body", fontSize=9,  fontName="Helvetica",      textColor=C["text"],   leading=14)
    style_mono  = S("mono", fontSize=8,  fontName="Courier",        textColor=C["text"],   leading=12)
    style_label = S("lbl",  fontSize=7,  fontName="Helvetica-Bold", textColor=C["dim"],    leading=10)

    W = A4[0] - 4*cm

    def hr(color=C["accent"], thick=1) -> HRFlowable:
        return HRFlowable(width="100%", thickness=thick, color=color, spaceAfter=6)

    def meta_table(rows: list[tuple[str, str]]) -> Table:
        t = Table(
            [[Paragraph(k, style_label), Paragraph(v or "—", style_body)] for k, v in rows],
            colWidths=[3.5*cm, W - 3.5*cm],
        )
        t.setStyle(TableStyle([
            ("FONTNAME",       (0,0), (-1,-1), "Helvetica"),
            ("FONTSIZE",       (0,0), (-1,-1), 8),
            ("ROWBACKGROUNDS", (0,0), (-1,-1),
             [colors.HexColor("#0d1117"), colors.HexColor("#111827")]),
            ("TEXTCOLOR",      (0,0), (0,-1), C["dim"]),
            ("TEXTCOLOR",      (1,0), (1,-1), C["text"]),
            ("GRID",           (0,0), (-1,-1), 0.3, colors.HexColor("#1e2a3a")),
            ("PADDING",        (0,0), (-1,-1), 5),
            ("VALIGN",         (0,0), (-1,-1), "TOP"),
        ]))
        return t

    story: list = []

    # Cover
    story.append(Spacer(1, 1*cm))
    story.append(Paragraph("APISec", style_h1))
    story.append(Paragraph("API Security Audit Report",
                            S("sub", fontSize=12, fontName="Helvetica", textColor=C["dim"])))
    story.append(Spacer(1, 4*mm))
    story.append(hr())
    story.append(Spacer(1, 4*mm))
    story.append(meta_table([
        ("Target",   scan["target"]),
        ("API Type", scan["api_type"]),
        ("Tests",    scan["tests"]),
        ("Status",   scan["status"].upper()),
        ("Date",     scan["created_at"][:19].replace("T", " ") + " UTC"),
        ("Duration", f"{scan['duration_sec'] or 0:.1f} s"),
        ("Scan ID",  scan_id),
        ("Tool",     "APISec v2.1 — PFE Security Audit"),
    ]))
    story.append(Spacer(1, 6*mm))

    # Severity summary
    story.append(Paragraph("Vulnerability Summary", style_h2))
    story.append(hr(C["dim"], 0.5))
    risk_map = {
        "CRITICAL": "Immediate exploitation possible",
        "HIGH":     "Exploitation likely",
        "MEDIUM":   "Conditional exploitation",
        "LOW":      "Difficult to exploit",
        "INFO":     "Informational / Observation",
    }
    sev_data = [["Severity", "Count", "Risk Level"]]
    for sev in SEV_ORDER:
        sev_data.append([sev, str(scan[sev.lower()]), risk_map[sev]])

    sev_table = Table(sev_data, colWidths=[4*cm, 2.5*cm, W-6.5*cm])
    ts = [
        ("FONTNAME",       (0,0), (-1,0), "Helvetica-Bold"),
        ("FONTSIZE",       (0,0), (-1,-1), 8),
        ("BACKGROUND",     (0,0), (-1,0), C["surface"]),
        ("TEXTCOLOR",      (0,0), (-1,0), C["accent"]),
        ("GRID",           (0,0), (-1,-1), 0.3, colors.HexColor("#1e2a3a")),
        ("PADDING",        (0,0), (-1,-1), 5),
        ("ROWBACKGROUNDS", (0,1), (-1,-1),
         [colors.HexColor("#0d1117"), colors.HexColor("#111827")]),
    ]
    for i, sev in enumerate(SEV_ORDER, 1):
        cnt = scan[sev.lower()]
        if cnt > 0:
            ts += [
                ("TEXTCOLOR", (0,i), (0,i), C[sev]),
                ("FONTNAME",  (0,i), (0,i), "Helvetica-Bold"),
                ("TEXTCOLOR", (1,i), (1,i), C[sev]),
                ("FONTNAME",  (1,i), (1,i), "Helvetica-Bold"),
            ]
        else:
            ts.append(("TEXTCOLOR", (0,i), (-1,i), C["dim"]))
    sev_table.setStyle(TableStyle(ts))
    story.append(sev_table)
    story.append(Spacer(1, 4*mm))

    if scan["findings"] == 0:
        story.append(Paragraph(
            "✓ No vulnerabilities detected during this scan.",
            S("ok", fontSize=10, fontName="Helvetica-Bold",
              textColor=C["LOW"], spaceBefore=8),
        ))

    # Findings detail
    if findings_rows:
        story.append(PageBreak())
        story.append(Paragraph("Findings Detail", style_h2))
        story.append(hr())
        story.append(Spacer(1, 2*mm))

        for i, f in enumerate([dict(r) for r in findings_rows], 1):
            sev   = (f.get("severity") or "INFO").upper()
            color = C.get(sev, C["INFO"])

            ht = Table([[
                Paragraph(f"#{i:02d}",                S("fn", fontSize=9, fontName="Helvetica-Bold", textColor=C["accent"])),
                Paragraph(f"[{sev}]",                 S("fs", fontSize=9, fontName="Helvetica-Bold", textColor=color)),
                Paragraph(f.get("vuln_id") or "—",    S("fi", fontSize=8, fontName="Courier",        textColor=C["dim"])),
                Paragraph(f.get("vuln_type") or "Unknown", S("ft", fontSize=9, fontName="Helvetica-Bold", textColor=C["text"])),
            ]], colWidths=[1*cm, 2*cm, 3*cm, W-6*cm])
            ht.setStyle(TableStyle([
                ("BACKGROUND", (0,0), (-1,-1), colors.HexColor("#111827")),
                ("LINEBELOW",  (0,0), (-1,-1), 1.5, color),
                ("PADDING",    (0,0), (-1,-1), 5),
                ("VALIGN",     (0,0), (-1,-1), "MIDDLE"),
            ]))
            story.append(ht)

            detail_rows = [
                ("Endpoint",    f.get("endpoint")),
                ("Method",      f.get("method")),
                ("OWASP",       f.get("owasp")),
                ("CWE",         f.get("cwe")),
                ("Confidence",  f.get("confidence")),
                ("Parameter",   f.get("parameter")),
                ("Payload",     f.get("payload")),
                ("Evidence",    f.get("evidence")),
                ("Description", f.get("description")),
                ("Solution",    f.get("solution")),
                ("Reference",   f.get("reference")),
            ]
            detail_rows = [(k, v) for k, v in detail_rows if v]

            if detail_rows:
                dt = Table(
                    [[Paragraph(k, style_label),
                      Paragraph(str(v)[:400],
                                style_mono if k in ("Payload","Evidence") else style_body)]
                     for k, v in detail_rows],
                    colWidths=[2.8*cm, W-2.8*cm],
                )
                dt.setStyle(TableStyle([
                    ("FONTSIZE",       (0,0), (-1,-1), 8),
                    ("ROWBACKGROUNDS", (0,0), (-1,-1),
                     [colors.HexColor("#0a0e1a"), colors.HexColor("#0d1117")]),
                    ("GRID",    (0,0), (-1,-1), 0.2, colors.HexColor("#1a2030")),
                    ("PADDING", (0,0), (-1,-1), 4),
                    ("VALIGN",  (0,0), (-1,-1), "TOP"),
                ]))
                story.append(dt)

            story.append(Spacer(1, 3*mm))

    # Footer
    story.append(Spacer(1, 1*cm))
    story.append(hr(C["dim"], 0.5))
    story.append(Paragraph(
        f"Generated by APISec v2.1 — PFE Security Audit Tool — {_now_iso()} UTC",
        S("footer", fontSize=7, fontName="Helvetica", textColor=C["dim"], alignment=1),
    ))

    doc.build(story)
    buf.seek(0)
    fname = f"apisec_report_{scan_id[:8]}_{datetime.now().strftime('%Y%m%d')}.pdf"
    return send_file(buf, mimetype="application/pdf",
                     as_attachment=True, download_name=fname)


# ══════════════════════════════════════════════════════════════════════════════
# API — UTILITIES
# ══════════════════════════════════════════════════════════════════════════════

@app.route("/api/wordlists")
def wordlists() -> Response:
    wl_dir = BASE_DIR / "wordlists"
    if not wl_dir.exists():
        return jsonify([])
    return jsonify(sorted(f.name for f in wl_dir.glob("*.txt")))


@app.route("/api/health")
def health() -> Response:
    return jsonify({
        "status":       "ok",
        "version":      "2.1",
        "active_scans": len(_registry.active_ids()),
        "db":           str(DB_PATH),
    })


# ══════════════════════════════════════════════════════════════════════════════
# AI ASSISTANT ENDPOINTS
# ══════════════════════════════════════════════════════════════════════════════

def _call_groq(messages: list[dict], system: str) -> str:
    """Call Groq API — reads key from os.environ at call time (supports runtime updates)."""
    import http.client
    import ssl

    # Always read from os.environ at call time — supports keys set via /api/ai/setup
    key   = os.environ.get("GROQ_API_KEY", "").strip()
    model = os.environ.get("GROQ_MODEL", GROQ_MODEL).strip()

    if not key:
        raise ValueError(
            "GROQ_API_KEY not set. "
            "Click the AI bubble and connect your Groq API key."
        )

    groq_messages = [{"role": "system", "content": system}] + messages
    payload = json.dumps({
        "model":       model,
        "messages":    groq_messages,
        "max_tokens":  1024,
        "temperature": 0.3,
    })

    ctx  = ssl.create_default_context()
    conn = http.client.HTTPSConnection("api.groq.com", timeout=30, context=ctx)
    conn.request(
        "POST",
        "/openai/v1/chat/completions",
        body    = payload,
        headers = {
            "Content-Type":  "application/json",
            "Authorization": "Bearer " + key,
        },
    )
    resp = conn.getresponse()
    body = resp.read().decode("utf-8")
    conn.close()

    if resp.status == 401:
        raise ValueError("Invalid Groq API key — create a new one at console.groq.com")
    if resp.status == 403:
        raise ValueError("Groq API forbidden (403) — key may be revoked or quota exceeded")
    if resp.status == 429:
        raise ValueError("Groq rate limit reached — wait a moment and try again")
    if resp.status >= 400:
        raise ValueError("Groq API error " + str(resp.status) + ": " + body[:200])

    data = json.loads(body)
    return data["choices"][0]["message"]["content"]


def _call_claude(messages: list[dict], system: str) -> str:
    """Call Anthropic Claude API."""
    import urllib.request
    if not ANTHROPIC_KEY:
        raise ValueError("ANTHROPIC_API_KEY not set.")
    payload = json.dumps({
        "model":      CLAUDE_MODEL,
        "max_tokens": 1024,
        "system":     system,
        "messages":   messages,
    }).encode("utf-8")
    req = urllib.request.Request(
        "https://api.anthropic.com/v1/messages",
        data    = payload,
        headers = {
            "Content-Type":      "application/json",
            "x-api-key":         ANTHROPIC_KEY,
            "anthropic-version": "2023-06-01",
        },
        method = "POST",
    )
    with urllib.request.urlopen(req, timeout=30) as resp:
        data = json.loads(resp.read().decode("utf-8"))
    return data["content"][0]["text"]


def _call_ollama(messages: list[dict], system: str) -> str:
    """Call local Ollama API — no internet, no key needed."""
    import http.client
    import urllib.parse

    ollama_url   = os.environ.get("OLLAMA_URL",   OLLAMA_URL)
    ollama_model = os.environ.get("OLLAMA_MODEL", OLLAMA_MODEL)

    ollama_messages = [{"role": "system", "content": system}] + messages
    payload = json.dumps({
        "model":    ollama_model,
        "messages": ollama_messages,
        "stream":   False,
    })

    parsed = urllib.parse.urlparse(ollama_url)
    host   = parsed.hostname or "localhost"
    port   = parsed.port or 11434

    conn = http.client.HTTPConnection(host, port, timeout=300)
    conn.request(
        "POST", "/api/chat",
        body    = payload,
        headers = {"Content-Type": "application/json"},
    )
    resp = conn.getresponse()
    body = resp.read().decode("utf-8")
    conn.close()

    if resp.status == 404:
        raise ValueError("Ollama endpoint not found — make sure Ollama is running: ollama serve")
    if resp.status >= 400:
        raise ValueError("Ollama error " + str(resp.status) + ": " + body[:200])

    data = json.loads(body)
    return data["message"]["content"]



def _ai_respond(messages: list[dict], system: str) -> str:
    """Route to the configured AI provider: groq | ollama | claude"""
    provider = os.environ.get("APISEC_AI_PROVIDER", AI_PROVIDER).lower()
    if provider == "groq":
        return _call_groq(messages, system)
    elif provider == "ollama":
        return _call_ollama(messages, system)
    elif provider == "claude":
        return _call_claude(messages, system)
    else:
        raise ValueError("Unknown provider: '" + provider + "'. Use: groq | ollama | claude")


# ══════════════════════════════════════════════════════════════════════════════
# AI ASSISTANT ENDPOINTS
# ══════════════════════════════════════════════════════════════════════════════

def _save_env_key(key: str, value: str) -> None:
    """Upsert a KEY=VALUE line in .env file."""
    env_path = BASE_DIR / ".env"
    lines: list[str] = []
    if env_path.exists():
        with open(env_path, encoding="utf-8") as fh:
            lines = fh.readlines()
    found = False
    for i, line in enumerate(lines):
        if line.strip().startswith(key + "=") or line.strip().startswith(key + " ="):
            lines[i] = key + "=" + value + "\n"
            found = True
            break
    if not found:
        lines.append(key + "=" + value + "\n")
    with open(env_path, "w", encoding="utf-8") as fh:
        fh.writelines(lines)


@app.route("/api/ai/setup", methods=["POST"])
def ai_setup() -> tuple[Response, int]:
    """POST /api/ai/setup — Validate and save AI provider key."""
    data     = request.get_json(force=True, silent=True) or {}
    provider = (data.get("provider") or "groq").lower()
    api_key  = (data.get("api_key")  or "").strip()

    global AI_PROVIDER, GROQ_API_KEY

    if provider == "groq":
        if not api_key:
            return jsonify({"error": "Groq API key is required"}), 400

        try:
            import http.client, ssl
            payload = json.dumps({
                "model":    os.environ.get("GROQ_MODEL", GROQ_MODEL),
                "messages": [{"role": "user", "content": "hi"}],
                "max_tokens": 5,
            })
            ctx  = ssl.create_default_context()
            conn = http.client.HTTPSConnection("api.groq.com", timeout=15, context=ctx)
            conn.request("POST", "/openai/v1/chat/completions",
                body    = payload,
                headers = {
                    "Content-Type":  "application/json",
                    "Authorization": "Bearer " + api_key,
                })
            resp   = conn.getresponse()
            status = resp.status
            resp.read()
            conn.close()
            if status in (401, 403):
                return jsonify({"error": "Invalid API key — check your key on console.groq.com"}), 401
            if status == 404:
                return jsonify({"error": "Model not found: " + GROQ_MODEL}), 404
        except Exception as exc:
            app.logger.warning("Groq validation error: %s", exc)

        os.environ["GROQ_API_KEY"]        = api_key
        os.environ["APISEC_AI_PROVIDER"]  = "groq"
        GROQ_API_KEY = api_key
        _save_env_key("GROQ_API_KEY",      api_key)
        _save_env_key("APISEC_AI_PROVIDER","groq")
        return jsonify({"ok": True, "provider": "groq",
                        "model": os.environ.get("GROQ_MODEL", GROQ_MODEL)})

    elif provider == "ollama":
        os.environ["APISEC_AI_PROVIDER"] = "ollama"
        _save_env_key("APISEC_AI_PROVIDER", "ollama")
        return jsonify({"ok": True, "provider": "ollama",
                        "model": os.environ.get("OLLAMA_MODEL", OLLAMA_MODEL)})

    return jsonify({"error": "Unknown provider: " + provider}), 400


@app.route("/api/ai/config")
def ai_config() -> Response:
    """GET /api/ai/config — Return current AI provider info."""
    ollama_available = False
    try:
        import http.client as _hc
        c = _hc.HTTPConnection("localhost", 11434, timeout=3)
        c.request("GET", "/api/tags")
        r = c.getresponse(); r.read(); c.close()
        ollama_available = (r.status == 200)
    except Exception:
        pass

    current_provider = os.environ.get("APISEC_AI_PROVIDER", AI_PROVIDER).lower()
    current_groq     = os.environ.get("GROQ_API_KEY", GROQ_API_KEY)

    model = {
        "groq":   os.environ.get("GROQ_MODEL", GROQ_MODEL),
        "claude": CLAUDE_MODEL,
        "ollama": os.environ.get("OLLAMA_MODEL", OLLAMA_MODEL),
    }.get(current_provider, "unknown")

    ready = (
        (current_provider == "groq"   and bool(current_groq))
        or (current_provider == "claude" and bool(ANTHROPIC_KEY))
        or (current_provider == "ollama" and ollama_available)
    )

    return jsonify({
        "provider":         current_provider,
        "model":            model,
        "ollama_available": ollama_available,
        "groq_key_set":     bool(current_groq),
        "ready":            ready,
    })


@app.route("/api/ai/analyze/<scan_id>", methods=["POST"])
def ai_analyze(scan_id: str) -> tuple[Response, int]:
    """POST /api/ai/analyze/<scan_id> — Auto-analyze completed scan."""
    db   = get_db()
    scan = db.execute("SELECT * FROM scans WHERE id=?", (scan_id,)).fetchone()
    if not scan:
        return jsonify({"error": "Scan not found"}), 404

    findings = db.execute(
        "SELECT * FROM findings WHERE scan_id=? ORDER BY CASE severity "
        "WHEN 'CRITICAL' THEN 0 WHEN 'HIGH' THEN 1 WHEN 'MEDIUM' THEN 2 "
        "WHEN 'LOW' THEN 3 ELSE 4 END",
        (scan_id,),
    ).fetchall()

    findings_list = [dict(f) for f in findings]

    if not findings_list:
        return jsonify({
            "analysis": (
                "**No vulnerabilities detected** on this target.\n\n"
                "The scan completed without finding any security issues. "
                "Consider running a deeper scan or manual testing for business logic flaws."
            )
        })

    prompt = (
        "Analyze these API security findings from a scan of " + scan["target"] + ":\n\n"
        "API Type: " + scan["api_type"] + "\n"
        "Tests run: " + scan["tests"] + "\n"
        "Duration: " + str(scan["duration_sec"] or 0) + "s\n\n"
        "FINDINGS (" + str(len(findings_list)) + " total):\n"
        + json.dumps(findings_list, indent=2, ensure_ascii=False)[:6000] +
        "\n\nProvide:\n"
        "1. **Executive Summary** (2-3 sentences, non-technical)\n"
        "2. **Critical Attack Chains** — related findings that combine into a bigger threat\n"
        "3. **Top 3 Priorities** — what to fix first and why\n"
        "4. **Overall Risk Level** — CRITICAL/HIGH/MEDIUM/LOW with justification\n"
        "5. **Quick Wins** — easiest fixes with highest impact\n\n"
        "Use markdown. Be direct and actionable."
    )

    try:
        analysis = _ai_respond([{"role": "user", "content": prompt}], AI_SYSTEM_PROMPT)
        return jsonify({"analysis": analysis, "provider": AI_PROVIDER})
    except Exception as exc:
        app.logger.error("AI analyze error: %s", exc)
        return jsonify({"error": str(exc)}), 500


@app.route("/api/ai/chat", methods=["POST"])
def ai_chat() -> tuple[Response, int]:
    """POST /api/ai/chat — Multi-turn chat with optional scan context."""
    data     = request.get_json(force=True, silent=True) or {}
    messages = data.get("messages", [])
    scan_id  = data.get("scan_id", "")

    if not messages:
        return jsonify({"error": "No messages provided"}), 400

    system = AI_SYSTEM_PROMPT
    if scan_id:
        db   = get_db()
        scan = db.execute("SELECT * FROM scans WHERE id=?", (scan_id,)).fetchone()
        if scan:
            findings = db.execute(
                "SELECT vuln_id, vuln_type, severity, endpoint, evidence, description "
                "FROM findings WHERE scan_id=? ORDER BY CASE severity "
                "WHEN 'CRITICAL' THEN 0 WHEN 'HIGH' THEN 1 ELSE 2 END LIMIT 20",
                (scan_id,),
            ).fetchall()
            ctx = {
                "target":   scan["target"],
                "api_type": scan["api_type"],
                "findings": [dict(f) for f in findings],
                "summary":  {
                    "critical": scan["critical"], "high": scan["high"],
                    "medium":   scan["medium"],   "low":  scan["low"],
                },
            }
            system += "\n\nCURRENT SCAN CONTEXT:\n" + json.dumps(ctx, indent=2, ensure_ascii=False)[:4000]

    try:
        reply = _ai_respond(messages, system)
        return jsonify({"reply": reply, "provider": AI_PROVIDER})
    except Exception as exc:
        app.logger.error("AI chat error: %s", exc)
        return jsonify({"error": str(exc)}), 500


# ══════════════════════════════════════════════════════════════════════════════
# ERROR HANDLERS
# ══════════════════════════════════════════════════════════════════════════════

@app.errorhandler(404)
def not_found(_e: Any) -> tuple[Response, int]:
    return jsonify({"error": "Endpoint not found"}), 404

@app.errorhandler(405)
def method_not_allowed(_e: Any) -> tuple[Response, int]:
    return jsonify({"error": "Method not allowed"}), 405

@app.errorhandler(500)
def internal_error(e: Any) -> tuple[Response, int]:
    app.logger.exception("500 error")
    return jsonify({"error": "Internal server error", "detail": str(e)}), 500


# ══════════════════════════════════════════════════════════════════════════════
# ENTRY POINT
# ══════════════════════════════════════════════════════════════════════════════

def _print_startup() -> None:
    print("\n".join([
        "",
        "  ╔══════════════════════════════════════════════╗",
        "  ║          APISec Web Interface v2.1          ║",
        "  ║     API Security Audit — PFE Project        ║",
        "  ╠══════════════════════════════════════════════╣",
        "  ║  URL     :  http://localhost:5000           ║",
        f"  ║  DB      :  {str(DB_PATH)[-34:]:<34} ║",
        f"  ║  Reports :  {str(REPORTS)[-34:]:<34} ║",
        "  ╚══════════════════════════════════════════════╝",
        "",
    ]))


if __name__ == "__main__":
    init_db()
    _print_startup()
    app.run(host="0.0.0.0", port=5000, debug=False, threaded=True)