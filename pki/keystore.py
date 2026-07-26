"""
keystore.py

Build PKCS#12 identities for every robot and combined keystores.
"""

from __future__ import annotations

import secrets
from pathlib import Path

from cryptography.hazmat.primitives.serialization import (
    BestAvailableEncryption,
    NoEncryption,
    pkcs12,
)

from pki.config import FleetConfig
from pki.models import Fleet, ProjectPaths
from pki.naming import p12_alias
from pki.utils import (
    ensure_directory,
    print_info,
    print_success,
    set_secure_permissions,
)


def get_or_generate_keystore_password(
    config: FleetConfig,
    paths: ProjectPaths,
) -> str:
    """
    Returns the keystore password from config or generates a new secure random password.
    Always persists the password to paths.keystore_password (output/keystore_password.txt).
    """
    if config.keystore.password and config.keystore.password.lower() != "auto":
        pwd = config.keystore.password
    elif paths.keystore_password.exists():
        pwd = paths.keystore_password.read_text(encoding="utf-8").strip()
        if not pwd:
            pwd = secrets.token_urlsafe(18)
    else:
        pwd = secrets.token_urlsafe(18)

    paths.ensure_directories()
    paths.keystore_password.write_text(pwd, encoding="utf-8")
    set_secure_permissions(paths.keystore_password)
    return pwd


def build_keystores(
    fleet: Fleet,
    config: FleetConfig,
    paths: ProjectPaths,
) -> str:
    """
    Generates one PKCS#12 identity per robot, plus a combined keystore bundle.
    Returns the effective password used for the keystores.
    """

    ensure_directory(paths.pkcs12)

    password = get_or_generate_keystore_password(config, paths)
    password_bytes = password.encode("utf-8") if password else None
    encryption = (
        BestAvailableEncryption(password_bytes)
        if password_bytes
        else NoEncryption()
    )

    # 1. Build individual PKCS#12 files
    for robot_cert in fleet.certificates:
        alias_str = p12_alias(robot_cert.robot, config.server)
        p12_file = paths.pkcs12 / f"{alias_str}.p12"

        print_info(f"Building {p12_file.name}")

        data = pkcs12.serialize_key_and_certificates(
            name=alias_str.encode("utf-8"),
            key=robot_cert.private_key,
            cert=robot_cert.certificate,
            cas=[fleet.root_ca.certificate],
            encryption_algorithm=encryption,
        )
        p12_file.write_bytes(data)
        set_secure_permissions(p12_file)

    # 2. Build combined keystore containing all certificates
    if fleet.certificates:
        combined_file = paths.output / config.keystore.filename
        print_info(f"Building combined keystore {combined_file.name}")

        primary_robot = fleet.certificates[0]
        primary_alias = p12_alias(primary_robot.robot, config.server)
        other_certs = [fleet.root_ca.certificate] + [
            rc.certificate for rc in fleet.certificates[1:]
        ]

        combined_data = pkcs12.serialize_key_and_certificates(
            name=primary_alias.encode("utf-8"),
            key=primary_robot.private_key,
            cert=primary_robot.certificate,
            cas=other_certs,
            encryption_algorithm=encryption,
        )
        combined_file.write_bytes(combined_data)
        set_secure_permissions(combined_file)

    print_success(
        f"Generated {len(fleet.certificates)} individual PKCS#12 file(s) and combined '{config.keystore.filename}'."
    )
    print_success(f"Saved keystore password to '{paths.keystore_password.name}'.")

    return password