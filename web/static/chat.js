/**
 * APISec -- chat.js  v3.0
 * AI Security Assistant
 * Providers: Groq | Ollama
 * Flow: Provider selection → Privacy warning → Key input → Chat
 */

"use strict";

const AiChat = (() => {

  // ── State ─────────────────────────────────────────────────────────────────
  let _open          = false;
  let _loading       = false;
  let _consentGiven  = false;   // true after user accepts warning this session
  let _provider      = null;    // selected provider: "groq"|"ollama"
  let _providerReady = false;   // true after successful key validation
  let _scanId        = null;
  let _history       = [];
  let _analyzed      = false;

  // Provider metadata — single source of truth
  const PROVIDERS = {
    groq: {
      name:        "Groq",
      model:       "llama-3.1-8b-instant",
      badge:       "FREE",
      icon:        "z",
      keyPrefix:   "gsk_",
      keyHint:     "gsk_...",
      setupUrl:    "console.groq.com",
      setupLabel:  "console.groq.com",
      step1:       "Go to console.groq.com and create a free account",
      step2:       "Click API Keys then Create API Key",
      step3:       'Copy your key (starts with gsk_) and paste it below',
      isCloud:     true,
      serverName:  "Groq",
    },
    ollama: {
      name:        "Ollama",
      model:       "llama3.2",
      badge:       "LOCAL",
      icon:        "O",
      isCloud:     false,
    },
  };

  // ── DOM helper ────────────────────────────────────────────────────────────
  const $ = (id) => document.getElementById(id);

  // ── Init ──────────────────────────────────────────────────────────────────
  function init() {
    // Bubble
    $("ai-bubble-btn").addEventListener("click", toggle);
    $("ai-close-btn").addEventListener("click",  close);
    $("ai-clear-btn").addEventListener("click",  clearChat);

    // Provider cards
    Object.keys(PROVIDERS).forEach(key => {
      const btn = $("setup-" + key + "-btn");
      if (btn) btn.addEventListener("click", () => selectProvider(key));
    });

    // Warning modal
    $("warn-accept-btn").addEventListener("click",  onWarningAccept);
    $("warn-decline-btn").addEventListener("click", onWarningDecline);

    // Key input modal
    $("setup-cancel-btn").addEventListener("click",  hideKeyModal);
    $("setup-confirm-btn").addEventListener("click", submitKey);
    $("setup-key-input").addEventListener("keydown", (e) => {
      if (e.key === "Enter") submitKey();
    });

    // Chat
    $("ai-send-btn").addEventListener("click", sendMessage);
    $("ai-prov-switch").addEventListener("click", resetToSetup);
    $("ai-clear-btn").addEventListener("click", clearChat);
    $("ai-input").addEventListener("keydown", (e) => {
      if (e.key === "Enter" && !e.shiftKey) {
        e.preventDefault();
        sendMessage();
      }
    });
    $("ai-input").addEventListener("input", () => {
      const ta = $("ai-input");
      ta.style.height = "auto";
      ta.style.height = Math.min(ta.scrollHeight, 120) + "px";
    });

    checkServerConfig();
  }

  // ── Open / Close ──────────────────────────────────────────────────────────
  function toggle() { _open ? close() : open(); }

  function open() {
    _open = true;
    $("ai-panel").classList.add("open");
    $("ai-panel").setAttribute("aria-hidden", "false");
    $("ai-bubble-btn").classList.add("active");
    $("ai-notif-dot").style.display = "none";

    if (_consentGiven && _providerReady) {
      showScreen("chat");
      $("ai-input").focus();
    } else {
      showScreen("setup");
    }
  }

  function close() {
    _open = false;
    $("ai-panel").classList.remove("open");
    $("ai-panel").setAttribute("aria-hidden", "true");
    $("ai-bubble-btn").classList.remove("active");
  }

  // ── Screen management ─────────────────────────────────────────────────────
  function showScreen(name) {
    // name: "setup" | "chat"
    $("ai-setup-screen").style.display = name === "setup" ? "flex" : "none";
    $("ai-chat-screen").style.display  = name === "chat"  ? "flex" : "none";
  }

  function resetToSetup() {
    _consentGiven  = false;
    _providerReady = false;
    _provider      = null;
    showScreen("setup");
  }

  // ── Provider selection ────────────────────────────────────────────────────
  function selectProvider(key) {
    _provider = key;
    const meta = PROVIDERS[key];

    if (!meta.isCloud) {
      // Ollama: no warning, no key — just connect
      connectOllama();
      return;
    }

    // Cloud provider: show privacy warning
    $("warn-provider-name").textContent = meta.name;
    $("warn-server-name").textContent   = meta.serverName;
    $("ai-warning-modal").classList.add("open");
  }

  // ── Warning modal ─────────────────────────────────────────────────────────
  function onWarningAccept() {
    $("ai-warning-modal").classList.remove("open");
    const meta = PROVIDERS[_provider];

    // If key already configured server-side for this provider — consent done
    if (_providerReady && _provider === _serverProvider) {
      _consentGiven = true;
      showScreen("chat");
      $("ai-input").focus();
      addMessage("assistant",
        "Welcome back! I am ready to analyze your API security findings. " +
        "Run a scan or ask me anything about API security."
      );
      return;
    }

    // Show key input modal configured for this provider
    showKeyModal(meta);
  }

  function onWarningDecline() {
    $("ai-warning-modal").classList.remove("open");
    _provider = null;
    addMessage("system",
      "Setup cancelled. Use Ollama for a fully local AI with no data sharing."
    );
  }

  // ── Key input modal ───────────────────────────────────────────────────────
  function showKeyModal(meta) {
    // Update modal content for this specific provider
    $("setup-modal-title").textContent  = "Connect " + meta.name + " API";
    $("setup-modal-icon").textContent   = meta.icon;
    $("setup-step1").textContent        = meta.step1;
    $("setup-step2").innerHTML          = meta.step2;
    $("setup-step3").textContent        = meta.step3;
    $("setup-key-input").placeholder    = meta.keyHint;
    $("setup-key-input").value          = "";
    $("setup-error").textContent        = "";
    $("setup-confirm-btn").disabled     = false;
    $("setup-confirm-btn").textContent  = "Validate & Connect";
    $("ai-setup-modal").classList.add("open");
    setTimeout(() => $("setup-key-input").focus(), 100);
  }

  function hideKeyModal() {
    $("ai-setup-modal").classList.remove("open");
    _provider = null;
  }

  async function submitKey() {
    const key  = ($("setup-key-input").value || "").trim();
    const meta = PROVIDERS[_provider];
    if (!meta) return;

    if (!key) {
      $("setup-error").textContent = "Please paste your API key.";
      return;
    }
    if (meta.keyPrefix && !key.startsWith(meta.keyPrefix)) {
      $("setup-error").textContent =
        meta.name + " keys start with " + meta.keyPrefix + " -- check your key.";
      return;
    }

    $("setup-confirm-btn").disabled    = true;
    $("setup-confirm-btn").textContent = "Validating...";
    $("setup-error").textContent       = "";

    try {
      const r    = await fetch("/api/ai/setup", {
        method:  "POST",
        headers: { "Content-Type": "application/json" },
        body:    JSON.stringify({ provider: _provider, api_key: key }),
      });
      const data = await r.json();

      if (!r.ok) {
        $("setup-error").textContent       = data.error || "Invalid key.";
        $("setup-confirm-btn").disabled    = false;
        $("setup-confirm-btn").textContent = "Validate & Connect";
        return;
      }

      // Connected
      $("ai-setup-modal").classList.remove("open");
      _providerReady  = true;
      _consentGiven   = true;
      _serverProvider = _provider;
      updateProviderBar(meta.name + " - " + data.model, true);
      showScreen("chat");
      $("ai-input").focus();
      addMessage("assistant",
        "**" + meta.name + " connected successfully!**\n\n" +
        "I am ready to analyze your API security findings. " +
        "Run a scan and I will automatically review the results, " +
        "or ask me anything about API security."
      );

    } catch (err) {
      $("setup-error").textContent       = "Connection error: " + err.message;
      $("setup-confirm-btn").disabled    = false;
      $("setup-confirm-btn").textContent = "Validate & Connect";
    }
  }

  // ── Ollama (no key needed) ────────────────────────────────────────────────
  async function connectOllama() {
    try {
      const r    = await fetch("/api/ai/setup", {
        method:  "POST",
        headers: { "Content-Type": "application/json" },
        body:    JSON.stringify({ provider: "ollama" }),
      });
      const data = await r.json();

      if (r.ok) {
        _providerReady  = true;
        _consentGiven   = true;
        _serverProvider = "ollama";
        updateProviderBar("Ollama - " + data.model, true);
        showScreen("chat");
        $("ai-input").focus();
        addMessage("assistant",
          "**Ollama connected!**\n\n" +
          "Running 100% locally -- no data leaves your machine. " +
          "Ask me anything about API security or run a scan for automatic analysis."
        );
      } else {
        addMessage("system",
          "Could not connect to Ollama. Make sure it is running:\n" +
          "ollama serve\nThen try again."
        );
      }
    } catch (err) {
      addMessage("system", "Ollama connection failed: " + err.message);
    }
  }

  // ── Server config check ───────────────────────────────────────────────────
  let _serverProvider = null;

  async function checkServerConfig() {
    try {
      const r    = await fetch("/api/ai/config");
      const data = await r.json();
      _serverProvider = data.provider;
      _providerReady  = data.ready;
      _provider       = data.provider;

      if (data.ready) {
        const meta = PROVIDERS[data.provider];
        updateProviderBar((meta ? meta.name : data.provider) + " - " + data.model, true);
      } else {
        updateProviderBar("Not configured", false);
      }
    } catch {
      updateProviderBar("AI unavailable", false);
    }
  }

  function updateProviderBar(label, ready) {
    const el = $("ai-provider-label");
    if (el) el.textContent = label;
    const dot  = $("ai-prov-dot");
    const text = $("ai-prov-text");
    if (dot)  dot.className   = "ai-prov-dot " + (ready ? "ready" : "error");
    if (text) text.textContent = label + (ready ? " -- ready" : " -- not configured");
  }

  // ── Scan context ──────────────────────────────────────────────────────────
  function setScanContext(scanId) {
    if (_scanId === scanId) return;
    _scanId   = scanId;
    _analyzed = false;
    if (!_open) $("ai-notif-dot").style.display = "block";
    setTimeout(() => autoAnalyze(scanId), 1200);
  }

  async function autoAnalyze(scanId) {
    if (_analyzed || !_providerReady) return;
    _analyzed = true;
    if (!_open) $("ai-notif-dot").style.display = "block";
    const tid = addTypingIndicator();
    try {
      const r    = await fetch("/api/ai/analyze/" + scanId, { method: "POST" });
      const data = await r.json();
      removeTypingIndicator(tid);
      addMessage("assistant", data.error ? "Analysis failed: " + data.error : data.analysis);
      if (!data.error) _history.push({ role: "assistant", content: data.analysis });
    } catch (err) {
      removeTypingIndicator(tid);
      addMessage("assistant", "Could not connect to AI: " + err.message);
    }
  }

  // ── Send message ──────────────────────────────────────────────────────────
  async function sendMessage() {
    const input = $("ai-input");
    const text  = (input.value || "").trim();
    if (!text || _loading) return;

    input.value        = "";
    input.style.height = "auto";
    addMessage("user", text);
    _history.push({ role: "user", content: text });
    $("ai-suggestions").style.display = "none";

    const tid = addTypingIndicator();
    _loading  = true;
    $("ai-send-btn").disabled = true;

    try {
      const r    = await fetch("/api/ai/chat", {
        method:  "POST",
        headers: { "Content-Type": "application/json" },
        body:    JSON.stringify({ messages: _history, scan_id: _scanId || "" }),
      });
      const data = await r.json();
      removeTypingIndicator(tid);
      if (data.error) {
        addMessage("assistant", "Error: " + data.error);
      } else {
        addMessage("assistant", data.reply);
        _history.push({ role: "assistant", content: data.reply });
      }
    } catch (err) {
      removeTypingIndicator(tid);
      addMessage("assistant", "Connection error: " + err.message);
    } finally {
      _loading = false;
      $("ai-send-btn").disabled = false;
      $("ai-input").focus();
    }
  }

  function suggest(btn) {
    $("ai-input").value = btn.textContent;
    sendMessage();
  }

  function clearChat() {
    _history  = [];
    _analyzed = false;
    $("ai-messages").innerHTML =
      '<div class="ai-welcome">' +
      '<div class="ai-welcome-icon">&#11041;</div>' +
      '<div class="ai-welcome-text"><strong>APISec AI Assistant</strong><br/>' +
      'Conversation cleared. Ask me anything about API security.</div>' +
      '</div>';
    $("ai-suggestions").style.display = "flex";
  }

  // ── DOM helpers ───────────────────────────────────────────────────────────
  function addMessage(role, text) {
    const msgs = $("ai-messages");
    const div  = document.createElement("div");
    div.className = "ai-msg ai-msg-" + role;
    if (role === "assistant") {
      div.innerHTML =
        '<div class="ai-msg-avatar">&#11041;</div>' +
        '<div class="ai-msg-bubble">' + renderMarkdown(text) + '</div>';
    } else if (role === "user") {
      div.innerHTML = '<div class="ai-msg-bubble">' + escHtml(text) + '</div>';
    } else {
      div.innerHTML = '<div class="ai-msg-system">' + renderMarkdown(text) + '</div>';
    }
    msgs.appendChild(div);
    msgs.scrollTop = msgs.scrollHeight;
    requestAnimationFrame(() => div.classList.add("visible"));
    return div;
  }

  function addTypingIndicator() {
    const msgs = $("ai-messages");
    const div  = document.createElement("div");
    div.className = "ai-msg ai-msg-assistant";
    div.id        = "ai-typing-" + Date.now();
    div.innerHTML =
      '<div class="ai-msg-avatar">&#11041;</div>' +
      '<div class="ai-msg-bubble ai-typing">' +
      '<span></span><span></span><span></span></div>';
    msgs.appendChild(div);
    msgs.scrollTop = msgs.scrollHeight;
    requestAnimationFrame(() => div.classList.add("visible"));
    return div.id;
  }

  function removeTypingIndicator(id) {
    const el = document.getElementById(id);
    if (el) el.remove();
  }

  function escHtml(s) {
    return String(s)
      .replace(/&/g,"&amp;").replace(/</g,"&lt;")
      .replace(/>/g,"&gt;").replace(/"/g,"&quot;");
  }

  function renderMarkdown(text) {
    return escHtml(text)
      .replace(/\*\*(.+?)\*\*/g,  "<strong>$1</strong>")
      .replace(/\*(.+?)\*/g,       "<em>$1</em>")
      .replace(/`([^`]+)`/g,       "<code>$1</code>")
      .replace(/^### (.+)$/gm,     "<h4>$1</h4>")
      .replace(/^## (.+)$/gm,      "<h3>$1</h3>")
      .replace(/^# (.+)$/gm,       "<h2>$1</h2>")
      .replace(/^[\*\-] (.+)$/gm,  "<li>$1</li>")
      .replace(/(<li>.*<\/li>)/gs, "<ul>$1</ul>")
      .replace(/\n{2,}/g,          "<br/><br/>")
      .replace(/\n/g,              "<br/>");
  }

  // ── Public API ────────────────────────────────────────────────────────────
  document.addEventListener("DOMContentLoaded", init);
  return { setScanContext, suggest, open, close, toggle };

})();

// Hook into scan completion
document.addEventListener("DOMContentLoaded", () => {
  if (typeof handleSSEMsg === "function") {
    const _orig = handleSSEMsg;
    window.handleSSEMsg = function(msg) {
      _orig(msg);
      if (msg.type === "done" && msg.scan_id) {
        AiChat.setScanContext(msg.scan_id);
      }
    };
  }
});