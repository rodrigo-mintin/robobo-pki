"""
manifest.py

Generates a JSON manifest file listing all generated PKI assets and metadata.
"""

from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path

from pki.config import FleetConfig
from pki.models import Fleet, ProjectPaths
from pki.naming import alias, hostname, url
from pki.utils import certificate_fingerprint, ensure_parent, print_info, print_success


def generate_manifest(
    fleet: Fleet,
    config: FleetConfig,
    paths: ProjectPaths,
) -> Path:
    """
    Generates a manifest.json file containing metadata for all Root CA and robot certificates.
    """
    print_info(f"Generating manifest at {paths.manifest.name}")

    root_cert = fleet.root_ca.certificate

    try:
        nvb_ca = root_cert.not_valid_before_utc
        nva_ca = root_cert.not_valid_after_utc
    except AttributeError:
        nvb_ca = root_cert.not_valid_before
        nva_ca = root_cert.not_valid_after

    ca_info = {
        "common_name": config.ca.common_name,
        "organization": config.ca.organization,
        "country": config.ca.country,
        "fingerprint": certificate_fingerprint(root_cert),
        "serial_number": str(root_cert.serial_number),
        "not_valid_before": nvb_ca.isoformat(),
        "not_valid_after": nva_ca.isoformat(),
        "certificate_file": paths.ca_certificate.name,
        "key_file": paths.ca_key.name,
    }

    robots_data = []
    for item in fleet.certificates:
        cert = item.certificate
        robot = item.robot

        try:
            nvb_robot = cert.not_valid_before_utc
            nva_robot = cert.not_valid_after_utc
        except AttributeError:
            nvb_robot = cert.not_valid_before
            nva_robot = cert.not_valid_after

        r_alias = alias(robot, config.server)
        r_hostname = hostname(robot, config.server)
        r_url = url(robot, config.server)

        robots_data.append({
            "id": robot.id,
            "alias": r_alias,
            "hostname": r_hostname,
            "url": r_url,
            "certificate_file": f"{r_alias}.crt",
            "key_file": f"{r_alias}.key",
            "p12_file": f"{r_alias}.p12",
            "fingerprint": certificate_fingerprint(cert),
            "serial_number": str(cert.serial_number),
            "not_valid_before": nvb_robot.isoformat(),
            "not_valid_after": nva_robot.isoformat(),
        })

    manifest_data = {
        "ca": ca_info,
        "server": {
            "prefix": config.server.prefix,
            "suffix": config.server.suffix,
            "port": config.server.port,
        },
        "total_robots": len(robots_data),
        "robots": robots_data,
        "generated_at": datetime.now(timezone.utc).isoformat(),
    }

    ensure_parent(paths.manifest)
    paths.manifest.write_text(json.dumps(manifest_data, indent=2), encoding="utf-8")

    print_success(f"Manifest generated with {len(robots_data)} robot(s).")
    return paths.manifest
