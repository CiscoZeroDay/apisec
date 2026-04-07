# core/requester.py
"""
Requester — Couche HTTP centralisée pour tout le projet.

Fonctionnalités :
  - Session réutilisable (keep-alive, cookies, connection pooling)
  - Retry automatique sur erreurs réseau (pas sur 4xx/5xx)
  - Logs automatiques de chaque requête via request_logger
  - Retourne None au lieu de crasher sur erreur réseau
  - Gestion complète des verbes HTTP (GET, POST, PUT, DELETE, OPTIONS, PATCH)
  - Injection/suppression de token d'authentification
  - Utilitaires statiques pour analyser les réponses
"""

from __future__ import annotations

import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry
from logger.logger import logger, request_logger


class Requester:
    """
    Couche HTTP centralisée et réutilisable.

    Utilisation :
        http = Requester("https://api.example.com", timeout=5)
        r    = http.get("/users")
        if Requester.is_success(r):
            print(r.json())
    """

    DEFAULT_HEADERS: dict[str, str] = {
        "User-Agent": "API-Audit-Tool/1.0",
        "Accept":     "application/json, */*",
    }

    def __init__(
        self,
        base_url:    str,
        timeout:     int = 5,
        max_retries: int = 2,
    ) -> None:
        """
        Args:
            base_url    : URL de base (ex: https://api.example.com)
            timeout     : Timeout HTTP en secondes (défaut: 5)
            max_retries : Nombre de tentatives sur erreur réseau (défaut: 2)
        """
        self.base_url = base_url.rstrip("/")
        self.timeout  = timeout

        self._session = requests.Session()

        # Retry uniquement sur erreurs réseau — pas sur 4xx/5xx
        # (on gère les status codes manuellement dans discovery)
        retry_strategy = Retry(
            total            = max_retries,
            backoff_factor   = 0.3,          # 0.3s, 0.6s, 1.2s entre les essais
            status_forcelist = [],            # aucun status code ne déclenche un retry
            allowed_methods  = [
                "GET", "POST", "PUT",
                "DELETE", "OPTIONS", "PATCH",
            ],
        )
        adapter = HTTPAdapter(max_retries=retry_strategy)
        self._session.mount("http://",  adapter)
        self._session.mount("https://", adapter)
        self._session.headers.update(self.DEFAULT_HEADERS)

    # =========================================================================
    #  Méthodes publiques — verbes HTTP
    # =========================================================================

    def get(self, path: str, **kwargs) -> requests.Response | None:
        """Effectue une requête GET."""
        return self._request("GET", path, **kwargs)

    def post(self, path: str, **kwargs) -> requests.Response | None:
        """Effectue une requête POST."""
        return self._request("POST", path, **kwargs)

    def put(self, path: str, **kwargs) -> requests.Response | None:
        """Effectue une requête PUT."""
        return self._request("PUT", path, **kwargs)

    def delete(self, path: str, **kwargs) -> requests.Response | None:
        """Effectue une requête DELETE."""
        return self._request("DELETE", path, **kwargs)

    def patch(self, path: str, **kwargs) -> requests.Response | None:
        """Effectue une requête PATCH."""
        return self._request("PATCH", path, **kwargs)

    def options(self, path: str, **kwargs) -> requests.Response | None:
        """Effectue une requête OPTIONS."""
        return self._request("OPTIONS", path, **kwargs)

    # =========================================================================
    #  Gestion de l'authentification
    # =========================================================================

    def set_token(self, token: str, scheme: str = "Bearer") -> None:
        """
        Injecte un token d'authentification dans tous les headers suivants.

        Args:
            token  : Le token (JWT, API key, etc.)
            scheme : Schéma d'auth (défaut: "Bearer")
        """
        self._session.headers.update({"Authorization": f"{scheme} {token}"})

    def clear_token(self) -> None:
        """Supprime le token d'authentification des headers."""
        self._session.headers.pop("Authorization", None)

    def set_header(self, key: str, value: str) -> None:
        """Ajoute ou remplace un header personnalisé pour toute la session."""
        self._session.headers.update({key: value})

    def clear_header(self, key: str) -> None:
        """Supprime un header personnalisé de la session."""
        self._session.headers.pop(key, None)

    # =========================================================================
    #  Méthode interne — logique commune à tous les verbes
    # =========================================================================

    def _request(
        self,
        method: str,
        path:   str,
        **kwargs,
    ) -> requests.Response | None:
        """
        Effectue la requête HTTP et gère les erreurs réseau.

        - path peut être absolu (http://...) ou relatif (/users)
        - Retourne None en cas d'erreur réseau (ConnectionError, Timeout)
        - Logue chaque requête via request_logger
        """
        # Construit l'URL — path absolu ou relatif
        url = path if path.startswith("http") else self.base_url + path

        try:
            r = self._session.request(
                method,
                url,
                timeout = kwargs.pop("timeout", self.timeout),
                **kwargs,
            )
            request_logger.log(
                method,
                url,
                r.status_code,
                r.elapsed.total_seconds(),
            )
            return r

        except requests.exceptions.ConnectionError:
            logger.debug(f"[requester] ConnectionError → {url}")
            return None

        except requests.exceptions.Timeout:
            logger.debug(f"[requester] Timeout ({self.timeout}s) → {url}")
            return None

        except requests.exceptions.TooManyRedirects:
            logger.debug(f"[requester] TooManyRedirects → {url}")
            return None

        except requests.exceptions.RequestException as e:
            logger.debug(f"[requester] RequestException {url} → {e}")
            return None

        except Exception as e:
            logger.debug(f"[requester] Unexpected error {url} → {e}")
            return None

    # =========================================================================
    #  Utilitaires statiques — analyse des réponses
    # =========================================================================

    @staticmethod
    def is_json(r: requests.Response) -> bool:
        """
        True si le Content-Type indique du JSON ou du GraphQL.
        """
        ct = r.headers.get("Content-Type", "")
        return "application/json" in ct or "application/graphql" in ct

    @staticmethod
    def is_xml(r: requests.Response) -> bool:
        """
        True si le Content-Type indique du XML ou du SOAP.
        """
        ct = r.headers.get("Content-Type", "")
        return any(t in ct for t in ("text/xml", "application/xml", "application/soap+xml"))

    @staticmethod
    def is_success(r: requests.Response | None) -> bool:
        """
        True si la réponse existe et que le status code est < 400.
        """
        return r is not None and r.status_code < 400

    @staticmethod
    def body_contains(r: requests.Response, *keys) -> bool:
        """
        True si le corps JSON contient au moins une des clés données.
        Gère les corps de type dict et list.

        Args:
            r    : La réponse HTTP
            keys : Clés à chercher dans le corps JSON
        """
        try:
            body = r.json()
            if isinstance(body, dict):
                return any(k in body for k in keys)
            if isinstance(body, list):
                return len(body) > 0
            return False
        except Exception:
            return False

    @staticmethod
    def safe_json(r: requests.Response | None) -> dict | list | None:
        """
        Parse le corps JSON sans lever d'exception.
        Retourne None si la réponse est None ou si le JSON est invalide.
        """
        if r is None:
            return None
        try:
            return r.json()
        except Exception:
            return None

    @staticmethod
    def get_header(r: requests.Response, key: str, default: str = "") -> str:
        """
        Retourne la valeur d'un header de réponse (insensible à la casse).
        """
        return r.headers.get(key, default)