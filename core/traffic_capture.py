# core/traffic_capture.py
"""
TrafficCapture — Real-time HTTP/HTTPS traffic capture and endpoint extraction.

Architecture:
    Uses mitmproxy's Python API (DumpMaster) to run a transparent proxy
    that intercepts all browser traffic. Captured flows are saved to disk
    via a custom FlowSaver addon, then converted to an OpenAPI/Swagger spec
    via mitmproxy2swagger. The resulting spec is parsed to produce a clean
    endpoints.json file compatible with the apisec scan pipeline.

Pipeline:
    Browser → mitmproxy proxy (port 8080) → target API
                      ↓
               traffic.mitm  (raw mitmproxy flows)
                      ↓
           mitmproxy2swagger (OpenAPI/Swagger spec)
                      ↓
              endpoints.json (apisec format)

SSL/TLS:
    mitmproxy generates a self-signed CA certificate on first run (~/.mitmproxy/).
    This module installs it automatically into the OS trust store so HTTPS
    traffic is captured transparently without browser warnings.

Compatibility:
    Tested with mitmproxy 11.x — uses FlowWriter addon instead of the
    deprecated save_stream_file option removed in mitmproxy 11.

Usage:
    capture = TrafficCapture(
        target_url  = "http://localhost:8888",
        proxy_port  = 8080,
        output_path = "endpoints.json",
    )
    result = capture.run()
"""

from __future__ import annotations

import asyncio
import json
import platform
import shutil
import subprocess
import threading
import time
import os
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional
from urllib.parse import urlparse

from logger.logger import logger


# =============================================================================
#  Constants
# =============================================================================

_DEFAULT_PROXY_PORT = 8080
_DEFAULT_PROXY_HOST = "127.0.0.1"
_MITM_CERT_DIR      = Path.home() / ".mitmproxy"
_MITM_CA_CERT_PEM   = _MITM_CERT_DIR / "mitmproxy-ca-cert.pem"
_MITM_CA_CERT_CRT   = _MITM_CERT_DIR / "mitmproxy-ca-cert.cer"

# Static asset extensions — not API endpoints
_IGNORE_EXTENSIONS = {
    ".js", ".css", ".png", ".jpg", ".jpeg", ".gif", ".svg",
    ".ico", ".woff", ".woff2", ".ttf", ".eot", ".map",
    ".html", ".htm", ".txt", ".pdf", ".zip", ".gz",
}

# Static paths — not API endpoints
_IGNORE_PATHS = {
    "/favicon.ico", "/robots.txt", "/sitemap.xml",
    "/manifest.json", "/service-worker.js",
}


# =============================================================================
#  CaptureResult
# =============================================================================

@dataclass
class CaptureResult:
    """Structured result from a traffic capture session."""

    target_url:   str
    api_type:     str            = "REST"
    endpoints:    list[str]      = field(default_factory=list)
    flow_count:   int            = 0
    api_flows:    int            = 0
    traffic_file: Optional[str] = None
    swagger_file: Optional[str] = None

    def to_dict(self) -> dict:
        return {
            "target_url": self.target_url,
            "api_type":   self.api_type,
            "endpoints":  self.endpoints,
            "source":     "traffic_capture",
        }


# =============================================================================
#  mitmproxy Addons
# =============================================================================

class _FlowSaver:
    """
    mitmproxy addon that saves every completed HTTP flow to a .mitm file.
    Replaces the deprecated save_stream_file option removed in mitmproxy 11.x.
    """

    def __init__(self, traffic_file: str) -> None:
        import mitmproxy.io as mitm_io
        self._file   = open(traffic_file, "wb")
        self._writer = mitm_io.FlowWriter(self._file)
        self._count  = 0

    def response(self, flow) -> None:
        """Save each completed flow (request + response) to disk."""
        try:
            self._writer.add(flow)
            self._count += 1
        except Exception as e:
            logger.debug(f"[capture] FlowSaver write error: {e}")

    def done(self) -> None:
        """Flush and close the file when mitmproxy shuts down."""
        try:
            self._file.flush()
            self._file.close()
        except Exception:
            pass

    @property
    def count(self) -> int:
        return self._count


class _RealtimeDisplay:
    """
    mitmproxy addon that displays captured API requests in real time.
    Only shows requests targeting the specified API host.
    Filters out static assets and duplicate paths.
    """

    def __init__(self, target_host: str) -> None:
        self.target_host  = target_host.lower()
        self.flow_count   = 0
        self.api_flows    = 0
        self._seen_paths: set[str] = set()

    def request(self, flow) -> None:
        """Display each intercepted API request in the terminal."""
        host   = flow.request.pretty_host.lower()
        method = flow.request.method
        url    = flow.request.pretty_url
        path   = flow.request.path.split("?")[0]

        self.flow_count += 1

        # Only display requests targeting our API
        if self.target_host not in host:
            return

        # Skip static assets
        ext = Path(path).suffix.lower()
        if ext in _IGNORE_EXTENSIONS or path in _IGNORE_PATHS:
            return

        self.api_flows += 1

        # Display each unique path only once
        if path not in self._seen_paths:
            self._seen_paths.add(path)
            print(f"  \033[92m[+]\033[0m {method:<7} {url}")


# =============================================================================
#  TrafficCapture
# =============================================================================

class TrafficCapture:
    """
    Real-time HTTP/HTTPS traffic capture using mitmproxy.

    Runs a transparent proxy, captures all browser traffic targeting
    the specified API, and produces an endpoints.json file ready
    for the apisec scan pipeline.

    Args:
        target_url   : URL of the API to capture (e.g. http://localhost:8888)
        proxy_port   : Local port for the mitmproxy listener (default: 8080)
        proxy_host   : Local host for the mitmproxy listener (default: 127.0.0.1)
        output_path  : Path for the generated endpoints.json file
        traffic_file : Path for the raw mitmproxy flow file (.mitm)
        swagger_file : Path for the intermediate OpenAPI spec (.yaml)
    """

    def __init__(
        self,
        target_url:   str,
        proxy_port:   int = _DEFAULT_PROXY_PORT,
        proxy_host:   str = _DEFAULT_PROXY_HOST,
        output_path:  str = "endpoints.json",
        traffic_file: str = "traffic.mitm",
        swagger_file: str = "swagger_captured.yaml",
    ) -> None:
        self.target_url   = target_url.rstrip("/")
        self.proxy_port   = proxy_port
        self.proxy_host   = proxy_host
        self.output_path  = output_path
        self.traffic_file = traffic_file
        self.swagger_file = swagger_file

        parsed           = urlparse(self.target_url)
        self.target_host = parsed.hostname or ""

        self._master:  Optional[object]                    = None
        self._saver:   Optional[_FlowSaver]                = None
        self._display: Optional[_RealtimeDisplay]          = None
        self._loop:    Optional[asyncio.AbstractEventLoop] = None

    # =========================================================================
    #  Dependency checks
    # =========================================================================

    @staticmethod
    def check_dependencies() -> bool:
        """Verify that mitmproxy, mitmproxy2swagger and pyyaml are installed."""
        missing = []

        try:
            from mitmproxy import options  # noqa: F401
            import mitmproxy.io            # noqa: F401
        except ImportError:
            missing.append("mitmproxy")

        if not shutil.which("mitmproxy2swagger"):
            missing.append("mitmproxy2swagger")

        try:
            import yaml  # noqa: F401
        except ImportError:
            missing.append("pyyaml")

        if missing:
            logger.error(
                f"[capture] Missing dependencies: {', '.join(missing)}\n"
                f"          Install with: pip install {' '.join(missing)}"
            )
            return False

        return True

    # =========================================================================
    #  SSL Certificate management
    # =========================================================================

    def _ensure_cert_exists(self) -> bool:
        """
        Generate the mitmproxy CA certificate by starting mitmdump briefly.
        mitmproxy creates the certificate automatically on first startup.
        """
        if _MITM_CA_CERT_PEM.exists():
            return True

        logger.info("[capture] Generating mitmproxy CA certificate (first run)...")

        try:
            # Start mitmdump briefly — certificate is generated on startup
            proc = subprocess.Popen(
                [
                    "mitmdump",
                    "--listen-host", self.proxy_host,
                    "--listen-port", str(self.proxy_port + 1),  # port différent pour éviter conflit
                    "--quiet",
                ],
                stdout = subprocess.DEVNULL,
                stderr = subprocess.DEVNULL,
            )
            time.sleep(3.0)  # Attendre la génération du certificat
            proc.terminate()
            proc.wait()

        except FileNotFoundError:
            logger.error("[capture] mitmdump not found — is mitmproxy installed?")
            return False
        except Exception as e:
            logger.debug(f"[capture] Cert generation error: {e}")

        if _MITM_CA_CERT_PEM.exists():
            logger.info(f"[capture] CA certificate generated: {_MITM_CA_CERT_PEM}")
            return True

        logger.warning("[capture] CA certificate not found after generation attempt")
        return False

    def install_certificate(self) -> bool:
        """
        Install the mitmproxy CA certificate into the OS trust store.
        Supports: Windows, macOS, Linux (Debian/Ubuntu, Fedora/RHEL/Arch).
        """
        if not self._ensure_cert_exists():
            self._print_manual_cert_instructions()
            return False

        system = platform.system()
        logger.info(f"[capture] Installing CA certificate on {system}...")

        try:
            if system == "Windows":
                return self._install_cert_windows()
            elif system == "Darwin":
                return self._install_cert_macos()
            elif system == "Linux":
                return self._install_cert_linux()
            else:
                logger.warning(f"[capture] Unsupported OS: {system}")
                self._print_manual_cert_instructions()
                return False
        except Exception as e:
            logger.error(f"[capture] Certificate installation error: {e}")
            self._print_manual_cert_instructions()
            return False

    def _install_cert_windows(self) -> bool:
        """Install the certificate into the Windows user certificate store."""
        cert = str(_MITM_CA_CERT_CRT if _MITM_CA_CERT_CRT.exists() else _MITM_CA_CERT_PEM)
        result = subprocess.run(
            ["certutil", "-addstore", "-user", "ROOT", cert],
            capture_output=True, text=True,
        )
        if result.returncode == 0:
            logger.info("[capture] Certificate installed into Windows trust store ✓")
            return True
        logger.error(f"[capture] certutil failed: {result.stderr.strip()}")
        self._print_manual_cert_instructions()
        return False

    def _install_cert_macos(self) -> bool:
        """Install the certificate into the macOS system Keychain."""
        result = subprocess.run(
            [
                "sudo", "security", "add-trusted-cert",
                "-d", "-r", "trustRoot",
                "-k", "/Library/Keychains/System.keychain",
                str(_MITM_CA_CERT_PEM),
            ],
            capture_output=True, text=True,
        )
        if result.returncode == 0:
            logger.info("[capture] Certificate installed into macOS Keychain ✓")
            return True
        logger.error(f"[capture] security command failed: {result.stderr.strip()}")
        self._print_manual_cert_instructions()
        return False

    def _install_cert_linux(self) -> bool:
        """Install the certificate into the Linux system trust store."""
        if shutil.which("update-ca-certificates"):
            # Debian / Ubuntu
            dest = Path("/usr/local/share/ca-certificates/mitmproxy-ca.crt")
            try:
                shutil.copy2(_MITM_CA_CERT_PEM, dest)
                result = subprocess.run(
                    ["sudo", "update-ca-certificates"],
                    capture_output=True, text=True,
                )
                if result.returncode == 0:
                    logger.info("[capture] Certificate installed (Debian/Ubuntu) ✓")
                    return True
            except Exception as e:
                logger.debug(f"[capture] Debian cert install error: {e}")

        elif shutil.which("update-ca-trust"):
            # Fedora / CentOS / RHEL / Arch
            dest = Path("/etc/pki/ca-trust/source/anchors/mitmproxy-ca.crt")
            try:
                shutil.copy2(_MITM_CA_CERT_PEM, dest)
                result = subprocess.run(
                    ["sudo", "update-ca-trust", "extract"],
                    capture_output=True, text=True,
                )
                if result.returncode == 0:
                    logger.info("[capture] Certificate installed (Fedora/RHEL) ✓")
                    return True
            except Exception as e:
                logger.debug(f"[capture] RHEL cert install error: {e}")

        logger.warning("[capture] Could not auto-install certificate on this Linux distro")
        self._print_manual_cert_instructions()
        return False

    def _print_manual_cert_instructions(self) -> None:
        """Print manual certificate installation instructions."""
        print(
            f"\n  \033[93m[!] Manual certificate installation required:\033[0m\n"
            f"      Certificate : {_MITM_CA_CERT_PEM}\n\n"
            f"      Windows : certutil -addstore -user ROOT \"{_MITM_CA_CERT_CRT}\"\n"
            f"      macOS   : sudo security add-trusted-cert -d -r trustRoot \\\n"
            f"                  -k /Library/Keychains/System.keychain \"{_MITM_CA_CERT_PEM}\"\n"
            f"      Linux   : sudo cp \"{_MITM_CA_CERT_PEM}\" "
            f"/usr/local/share/ca-certificates/mitmproxy-ca.crt\n"
            f"                sudo update-ca-certificates\n\n"
            f"      Or visit \033[92mhttp://mitm.it\033[0m while the proxy is running.\n"
        )

    # =========================================================================
    #  Proxy — start / stop
    # =========================================================================

    def _start_proxy(self) -> None:
        """
        Start the mitmproxy DumpMaster in a background daemon thread.
        Registers the _FlowSaver and _RealtimeDisplay addons.
        """
        from mitmproxy import options as mitm_options
        from mitmproxy.tools import dump as mitm_dump

        self._saver   = _FlowSaver(self.traffic_file)
        self._display = _RealtimeDisplay(self.target_host)

        async def _run() -> None:
            opts = mitm_options.Options(
                listen_host  = self.proxy_host,
                listen_port  = self.proxy_port,
                ssl_insecure = False,
            )
            self._master = mitm_dump.DumpMaster(
                opts,
                with_termlog = False,
                with_dumper  = False,
            )
            self._master.addons.add(self._saver)
            self._master.addons.add(self._display)

            try:
                await self._master.run()
            except Exception:
                pass

        self._loop = asyncio.new_event_loop()

        def _thread() -> None:
            asyncio.set_event_loop(self._loop)
            self._loop.run_until_complete(_run())

        thread = threading.Thread(target=_thread, daemon=True, name="mitmproxy")
        thread.start()

        # Wait for the proxy to be ready before returning
        time.sleep(2.0)
        logger.debug(f"[capture] Proxy ready on {self.proxy_host}:{self.proxy_port}")

    def _stop_proxy(self) -> None:
        """Gracefully shut down the mitmproxy DumpMaster and flush flows."""
        if self._master:
            try:
                self._master.shutdown()
                time.sleep(1.0)
            except Exception as e:
                logger.debug(f"[capture] Proxy shutdown: {e}")

    # =========================================================================
    #  Swagger generation
    # =========================================================================

    def _generate_swagger(self) -> bool:
        """
        Convert traffic.mitm → swagger_captured.yaml using mitmproxy2swagger.

        Two-pass approach:
        Pass 1 — generate initial spec (unknown paths marked 'ignore: true')
        Pass 2 — remove ignore flags then regenerate with all paths visible
        """
        if not Path(self.traffic_file).exists():
            logger.error(f"[capture] Traffic file not found: {self.traffic_file}")
            return False

        if Path(self.traffic_file).stat().st_size == 0:
            logger.error("[capture] Traffic file is empty — no flows were captured")
            return False

        logger.info("[capture] Generating OpenAPI spec from captured traffic...")

        # Force UTF-8 encoding to avoid Windows cp1252 issues
        env = {**os.environ, "PYTHONIOENCODING": "utf-8", "PYTHONUTF8": "1"}

        cmd = [
            "mitmproxy2swagger",
            "--input",      self.traffic_file,
            "--output",     self.swagger_file,
            "--api-prefix", self.target_url,
            "--format",     "flow",
        ]

        # Pass 1 — generate initial spec
        result = subprocess.run(
            cmd,
            capture_output = True,
            text           = True,
            encoding       = "utf-8",
            errors         = "replace",
            env            = env,
        )
        if result.returncode != 0:
            logger.error(
                f"[capture] mitmproxy2swagger pass 1 failed:\n{result.stderr.strip()}"
            )
            return False

        if not Path(self.swagger_file).exists():
            logger.error("[capture] Swagger file was not created by mitmproxy2swagger")
            return False

        # Pass 2 — remove 'ignore: true' flags
        self._remove_ignore_flags()

        # Pass 3 — regenerate with cleaned spec to apply ignore flag removal
        result = subprocess.run(
            cmd,
            capture_output = True,
            text           = True,
            encoding       = "utf-8",
            errors         = "replace",
            env            = env,
        )
        if result.returncode != 0:
            logger.warning(
                f"[capture] mitmproxy2swagger pass 2 warning:\n{result.stderr.strip()}"
            )

        logger.info(f"[capture] OpenAPI spec ready: {self.swagger_file}")
        return True

    def _remove_ignore_flags(self) -> None:
        """
        mitmproxy2swagger places captured paths in x-path-templates with 'ignore:' prefix.
        Remove those prefixes so paths are promoted to real endpoints on the next pass.
        """
        if not Path(self.swagger_file).exists():
            return
        try:
            with open(self.swagger_file, "r", encoding="utf-8") as f:
                content = f.read()

            # Remove 'ignore:' prefix from x-path-templates entries
            content = content.replace("- ignore:/", "- /")

            # Also handle standard ignore flags
            content = content.replace("ignore: true",   "ignore: false")
            content = content.replace("x-ignore: true", "x-ignore: false")

            with open(self.swagger_file, "w", encoding="utf-8") as f:
                f.write(content)

            logger.debug("[capture] Removed ignore flags from swagger spec")
        except Exception as e:
            logger.warning(f"[capture] Could not remove ignore flags: {e}")
            
    # =========================================================================
    #  Endpoint extraction
    # =========================================================================

    def _parse_swagger(self) -> list[str]:
        """
        Parse the generated OpenAPI spec and extract unique endpoint URLs.
        Filters out static assets, ignored paths, and duplicate entries.
        """
        import yaml

        if not Path(self.swagger_file).exists():
            logger.error(f"[capture] Swagger file not found: {self.swagger_file}")
            return []

        try:
            with open(self.swagger_file, "r", encoding="utf-8") as f:
                spec = yaml.safe_load(f)
        except Exception as e:
            logger.error(f"[capture] Failed to parse swagger file: {e}")
            return []

        if not spec or not isinstance(spec, dict):
            logger.error("[capture] Invalid or empty swagger spec")
            return []

        paths     = spec.get("paths", {})
        base      = self.target_url.rstrip("/")
        endpoints: list[str] = []
        seen:      set[str]  = set()

        for path, methods in paths.items():
            if not isinstance(methods, dict):
                continue

            # Skip static assets
            if Path(path).suffix.lower() in _IGNORE_EXTENSIONS:
                continue

            if path in _IGNORE_PATHS:
                continue

            url = f"{base}{path}"
            if url not in seen:
                seen.add(url)
                endpoints.append(url)
                logger.debug(f"    [capture] endpoint: {url}")

        logger.info(
            f"[capture] Extracted {len(endpoints)} unique endpoint(s) from spec"
        )
        return endpoints

    # =========================================================================
    #  Output
    # =========================================================================

    def _save_endpoints(self, endpoints: list[str]) -> None:
        """Save the extracted endpoints in apisec-compatible JSON format."""
        data = {
            "target_url": self.target_url,
            "api_type":   "REST",
            "endpoints":  endpoints,
            "source":     "traffic_capture",
        }
        try:
            with open(self.output_path, "w", encoding="utf-8") as f:
                json.dump(data, f, indent=2, ensure_ascii=False)
            logger.info(f"[capture] Endpoints saved to: {self.output_path}")
        except OSError as e:
            logger.error(f"[capture] Cannot write output file: {e}")

    # =========================================================================
    #  User interface helpers
    # =========================================================================

    def _print_banner(self) -> None:
        """Display proxy configuration instructions to the user."""
        print(f"""
  \033[94m╔══════════════════════════════════════════════════════╗
  ║           APISec — Traffic Capture Mode              ║
  ╚══════════════════════════════════════════════════════╝\033[0m

  \033[93m[→] Configure your browser proxy:\033[0m

      Address  : \033[92m{self.proxy_host}\033[0m
      Port     : \033[92m{self.proxy_port}\033[0m

  \033[93m[→] Navigate on:\033[0m \033[92m{self.target_url}\033[0m
      Login, browse, and use all features of the application.
      Every unique API endpoint you visit will be captured.

  \033[93m[→] Captured requests appear below in real time.\033[0m
  \033[93m[→] Press \033[91mENTER\033[93m when you have finished navigating.\033[0m
  \033[94m══════════════════════════════════════════════════════\033[0m
""")

    def _print_summary(self, result: CaptureResult) -> None:
        """Display a summary of the capture session."""
        print(f"""
  \033[94m══════════════════════════════════════════════════════\033[0m
  \033[92m[✓] Capture complete\033[0m

      Total requests captured  : {result.flow_count}
      API requests captured    : {result.api_flows}
      Unique endpoints found   : {len(result.endpoints)}
      Output file              : {self.output_path}

  \033[93m[→] Run scan:\033[0m
      apisec scan --input {self.output_path} --tests all
  \033[94m══════════════════════════════════════════════════════\033[0m
""")

    # =========================================================================
    #  run() — Main orchestrator
    # =========================================================================

    def run(self) -> CaptureResult:
        """
        Execute the full capture pipeline:

          1. Check dependencies (mitmproxy, mitmproxy2swagger, pyyaml)
          2. Install SSL/TLS CA certificate into OS trust store
          3. Start mitmproxy transparent proxy on configured port
          4. Display instructions and wait for user to navigate
          5. Stop proxy and flush captured flows to traffic.mitm
          6. Generate OpenAPI spec via mitmproxy2swagger (2 passes)
          7. Parse and filter endpoints from OpenAPI spec
          8. Save endpoints.json in apisec-compatible format

        Returns:
            CaptureResult — structured result with endpoints and session stats.
        """
        result = CaptureResult(target_url=self.target_url)

        # ── Step 1: Dependency check ──────────────────────────────────────────
        logger.info("[capture] Checking dependencies...")
        if not self.check_dependencies():
            return result

        # ── Step 2: SSL certificate ───────────────────────────────────────────
        logger.info("[capture] Installing SSL certificate...")
        cert_ok = self.install_certificate()
        if not cert_ok:
            logger.warning(
                "[capture] SSL certificate not installed — "
                "HTTPS traffic may not be captured. HTTP will still work."
            )

        # ── Step 3: Start proxy ───────────────────────────────────────────────
        logger.info(
            f"[capture] Starting proxy on {self.proxy_host}:{self.proxy_port}..."
        )
        try:
            self._start_proxy()
        except Exception as e:
            logger.error(f"[capture] Failed to start proxy: {e}")
            return result

        # ── Step 4: User navigation ───────────────────────────────────────────
        self._print_banner()

        try:
            input()
        except KeyboardInterrupt:
            print("\n  \033[91m[!] Capture interrupted by user.\033[0m")

        # ── Step 5: Stop proxy ────────────────────────────────────────────────
        print("\n  \033[93m[→] Stopping proxy — saving flows...\033[0m")
        self._stop_proxy()

        result.flow_count   = self._display.flow_count if self._display else 0
        result.api_flows    = self._display.api_flows  if self._display else 0
        result.traffic_file = self.traffic_file

        if result.flow_count == 0:
            logger.warning(
                "[capture] No traffic captured.\n"
                f"          Verify your browser proxy is set to "
                f"{self.proxy_host}:{self.proxy_port}"
            )
            return result

        logger.info(
            f"[capture] {result.flow_count} request(s) captured "
            f"({result.api_flows} targeting {self.target_url})"
        )

        # ── Step 6: Generate swagger ──────────────────────────────────────────
        if not self._generate_swagger():
            logger.error("[capture] Failed to generate OpenAPI spec")
            return result

        result.swagger_file = self.swagger_file

        # ── Step 7: Parse endpoints ───────────────────────────────────────────
        result.endpoints = self._parse_swagger()

        if not result.endpoints:
            logger.warning(
                "[capture] No endpoints extracted.\n"
                "          Try navigating more pages and re-running the capture."
            )
            return result

        # ── Step 8: Save endpoints.json ───────────────────────────────────────
        self._save_endpoints(result.endpoints)

        # ── Summary ───────────────────────────────────────────────────────────
        self._print_summary(result)

        return result