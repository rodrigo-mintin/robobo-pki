"""
config.py

Loads fleet.yml into strongly-typed configuration objects.
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

import yaml

from typing import Tuple


# =============================================================================
# Configuration models
# =============================================================================

@dataclass(frozen=True)
class CertificateAuthorityConfig:
    common_name: str
    organization: str
    country: str
    years_valid: int = 100

@dataclass(frozen=True)
class CertificatesConfig:
    validity_years: int = 100


@dataclass(frozen=True)
class ServerConfig:
    prefix: str
    suffix: str
    port: int


@dataclass(frozen=True)
class KeystoreConfig:
    filename: str
    password: str


@dataclass(frozen=True)
class FleetConfig:
    ca: CertificateAuthorityConfig
    certificates: CertificatesConfig
    server: ServerConfig
    keystore: KeystoreConfig
    robots: Tuple[str, ...]


# =============================================================================
# Public API
# =============================================================================

def load_config(path: str | Path) -> FleetConfig:

    path = Path(path)

    with path.open("r", encoding="utf8") as f:
        data = yaml.safe_load(f)

    ca = CertificateAuthorityConfig(
        common_name=data["ca"]["common_name"],
        organization=data["ca"]["organization"],
        country=data["ca"]["country"],
        years_valid=data["ca"].get("years_valid", 20),
    )

    server = ServerConfig(
        prefix=data["server"]["prefix"],
        suffix=data["server"]["suffix"],
        port=data["server"]["port"],
    )

    keystore = KeystoreConfig(
        filename=data["keystore"]["filename"],
        password=data["keystore"].get("password"),
    )

    robots = tuple(data.get("robots", []))

    certificates = CertificatesConfig(
        validity_years=data.get("certificates", {}).get(
            "validity_years",
            50,
        ),
    )

    return FleetConfig(
        ca=ca,
        certificates=certificates,
        server=server,
        keystore=keystore,
        robots=robots,
    )