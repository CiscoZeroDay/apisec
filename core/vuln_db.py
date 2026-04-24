# core/vuln_db.py
"""
VulnDB — Shared vulnerability knowledge base loader.

Loads vulnerability metadata from data/*.json files and provides
a clean interface for all scanners (REST, GraphQL, SOAP).

Usage:
    from core.vuln_db import VulnDB

    db  = VulnDB("graphql")        # loads data/graphql_vulns.json
    db  = VulnDB("rest")           # loads data/rest_vulns.json
    db  = VulnDB("soap")           # loads data/soap_vulns.json

    meta = db.get("introspection") # returns the metadata dict
    meta = db.get("AUTH-001")      # works with vuln_id too
    all  = db.entries              # list of (key, dict) tuples
"""

from __future__ import annotations

import json
import os
from typing import Optional

from logger.logger import logger


# Root of the project — one level above this file (core/)
_PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
_DATA_DIR     = os.path.join(_PROJECT_ROOT, "data")


class VulnDB:
    """
    Loads and queries a vulnerability knowledge base from data/<api_type>_vulns.json.

    Design principles:
      - Singleton per api_type — each JSON file is loaded only once.
      - Graceful degradation — if the file is missing or malformed,
        all queries return empty dicts (scanner continues without metadata).
      - Dual lookup — supports both semantic keys ("introspection") and
        vuln_id values ("GQL-S1").

    Args:
        api_type : "graphql" | "rest" | "soap"
    """

    # Class-level cache — one instance per api_type
    _instances: dict[str, "VulnDB"] = {}

    def __new__(cls, api_type: str) -> "VulnDB":
        api_type = api_type.lower()
        if api_type not in cls._instances:
            instance = super().__new__(cls)
            instance._api_type = api_type
            instance._db: dict       = {}
            instance._id_index: dict = {}   # vuln_id → entry
            instance._load()
            cls._instances[api_type] = instance
        return cls._instances[api_type]

    # -------------------------------------------------------------------------
    #  Loading
    # -------------------------------------------------------------------------

    def _load(self) -> None:
        path = os.path.join(_DATA_DIR, f"{self._api_type}_vulns.json")
        try:
            with open(path, "r", encoding="utf-8") as f:
                self._db = json.load(f)

            # Build secondary index: vuln_id → entry
            # Allows db.get("GQL-S1") in addition to db.get("introspection")
            for key, value in self._db.items():
                if key.startswith("_"):
                    continue
                vid = value.get("id")
                if vid:
                    self._id_index[vid] = value

            count = len([k for k in self._db if not k.startswith("_")])
            logger.debug(f"[vulndb] {self._api_type} — loaded {count} entries from {path}")

        except FileNotFoundError:
            logger.warning(
                f"[vulndb] {path} not found — "
                f"ScanResults for {self._api_type} will have empty metadata fields."
            )
        except json.JSONDecodeError as exc:
            logger.error(f"[vulndb] Malformed {path}: {exc}")

    # -------------------------------------------------------------------------
    #  Query interface
    # -------------------------------------------------------------------------

    def get(self, key: str) -> dict:
        """
        Return the metadata dict for a vulnerability.

        Accepts both semantic names ("introspection", "auth") and
        vuln_id values ("GQL-S1", "AUTH-001").

        Returns an empty dict if the key is not found.
        """
        return self._db.get(key) or self._id_index.get(key) or {}

    @property
    def entries(self) -> list[tuple[str, dict]]:
        """
        Return all (key, metadata_dict) pairs, excluding the _meta entry.
        Useful for --list-tests display.
        """
        return [
            (k, v) for k, v in self._db.items()
            if not k.startswith("_")
        ]

    @property
    def loaded(self) -> bool:
        """True if the knowledge base was loaded successfully."""
        return bool(self._db)

    def summary(self) -> str:
        count = len(self.entries)
        return f"VulnDB[{self._api_type}] — {count} entries"

    def __repr__(self) -> str:
        return self.summary()