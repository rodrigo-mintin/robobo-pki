"""
generator.py

High-level PKI generation and management orchestration.
"""

from __future__ import annotations

from pathlib import Path
from typing import List

from pki.ca import load_or_create_root_ca, verify_root_ca
from pki.certificates import (
    days_until_expiration,
    load_or_create_robot_certificate,
    verify_robot_certificate,
)
from pki.config import FleetConfig
from pki.keystore import build_keystores
from pki.manifest import generate_manifest
from pki.models import (
    Fleet,
    ProjectPaths,
    RobotCertificate,
    RootCA,
)
from pki.naming import alias, hostname, url
from pki.patterns import expand_patterns
from pki.utils import (
    certificate_fingerprint,
    print_header,
    print_info,
    print_success,
    print_warning,
)


def init_ca_command(config: FleetConfig, paths: ProjectPaths, force: bool = False) -> RootCA:
    """
    Initializes or loads the Root Certificate Authority.
    """
    print_header("Root CA Initialization")
    paths.ensure_directories()

    root_ca = load_or_create_root_ca(config, paths, force=force)

    is_valid, msg = verify_root_ca(root_ca)
    if is_valid:
        print_success(f"Root CA status: {msg}")
    else:
        print_warning(f"Root CA warning: {msg}")

    return root_ca


def generate_pki(
    config: FleetConfig,
    paths: ProjectPaths,
    force: bool = False,
    force_ca: bool = False,
    force_robots: bool = False,
) -> Fleet:
    """
    Main orchestration entrypoint for generating the Robobo PKI.
    Idempotently creates Root CA, robot certificates, PKCS#12 keystores, and manifest.
    """
    print_header("Initializing PKI Generation")
    paths.ensure_directories()

    ca_force = force or force_ca
    robots_force = force or force_robots

    root_ca = load_or_create_root_ca(config, paths, force=ca_force)

    robots = list(expand_patterns(config.robots))
    print_header(f"Processing Fleet ({len(robots)} robot identities)")

    robot_certs: List[RobotCertificate] = []
    for robot in robots:
        cert = load_or_create_robot_certificate(robot, root_ca, config, paths, force=robots_force)
        robot_certs.append(cert)

    fleet = Fleet(root_ca=root_ca, certificates=robot_certs)

    if robot_certs:
        print_header("Building PKCS#12 Keystores")
        build_keystores(fleet, config, paths)

    print_header("Generating Manifest")
    generate_manifest(fleet, config, paths)

    print_header("PKI Generation Complete")
    print_success(f"Successfully processed Root CA and {len(robot_certs)} robot certificate(s).")

    return fleet


def rebuild_keystores_command(config: FleetConfig, paths: ProjectPaths) -> Fleet:
    """
    Rebuilds PKCS#12 keystores and manifest from existing certificate files.
    """
    print_header("Rebuilding PKCS#12 Keystores & Manifest")
    paths.ensure_directories()

    root_ca = load_or_create_root_ca(config, paths)
    robots = list(expand_patterns(config.robots))

    robot_certs: List[RobotCertificate] = []
    for robot in robots:
        cert = load_or_create_robot_certificate(robot, root_ca, config, paths)
        robot_certs.append(cert)

    fleet = Fleet(root_ca=root_ca, certificates=robot_certs)

    if robot_certs:
        build_keystores(fleet, config, paths)

    generate_manifest(fleet, config, paths)

    print_success("Rebuild completed successfully.")
    return fleet


def renew_pki_command(config: FleetConfig, paths: ProjectPaths, days_threshold: int = 30) -> Fleet:
    """
    Inspects Root CA and robot certificates and renews any expiring within `days_threshold` days.
    """
    print_header(f"Renewing Certificates (Threshold: {days_threshold} days)")
    paths.ensure_directories()

    ca_force = False
    if paths.ca_certificate.exists():
        ca = load_or_create_root_ca(config, paths)
        ca_days = days_until_expiration(ca.certificate)
        if ca_days <= days_threshold:
            print_warning(f"Root CA expires in {ca_days} days. Regenerating Root CA!")
            ca_force = True

    root_ca = load_or_create_root_ca(config, paths, force=ca_force)
    robots = list(expand_patterns(config.robots))

    renewed_count = 0
    robot_certs: List[RobotCertificate] = []

    for robot in robots:
        c_path = paths.robots / f"{alias(robot, config.server)}.crt"
        force_robot = ca_force

        if not force_robot and c_path.exists():
            robot_cert = load_or_create_robot_certificate(robot, root_ca, config, paths)
            r_days = days_until_expiration(robot_cert.certificate)
            if r_days <= days_threshold:
                print_warning(f"Robot {robot.id} certificate expires in {r_days} days. Renewing!")
                force_robot = True

        cert = load_or_create_robot_certificate(robot, root_ca, config, paths, force=force_robot)
        if force_robot:
            renewed_count += 1
        robot_certs.append(cert)

    fleet = Fleet(root_ca=root_ca, certificates=robot_certs)

    if robot_certs:
        build_keystores(fleet, config, paths)

    generate_manifest(fleet, config, paths)

    print_success(f"Renewal process complete. Renewed {renewed_count} certificate(s).")
    return fleet


def list_fleet_command(config: FleetConfig, paths: ProjectPaths) -> None:
    """
    Displays a summary of Root CA and fleet certificate identities.
    """
    print_header("Robobo PKI Fleet Summary")

    if not (paths.ca_key.exists() and paths.ca_certificate.exists()):
        print_warning("Root CA has not been initialized yet. Run 'init-ca' or 'generate' first.")
        return

    root_ca = load_or_create_root_ca(config, paths)
    ca_valid, ca_msg = verify_root_ca(root_ca)
    ca_days = days_until_expiration(root_ca.certificate)

    print_info(f"Root CA Subject: {root_ca.subject.rfc4514_string()}")
    print_info(f"Root CA Status:  {'VALID' if ca_valid else 'INVALID'} ({ca_msg}, {ca_days} days remaining)")
    print_info(f"Root CA Fingerprint: {certificate_fingerprint(root_ca.certificate)}")

    robots = list(expand_patterns(config.robots))
    print(f"\nRobots ({len(robots)} Total):")
    print("-" * 85)
    print(f"{'ID':<8} {'ALIAS':<18} {'HOSTNAME':<22} {'CERT':<6} {'P12':<6} {'DAYS REMAINING':<15}")
    print("-" * 85)

    for robot in robots:
        r_alias = alias(robot, config.server)
        r_host = hostname(robot, config.server)
        crt_file = paths.robots / f"{r_alias}.crt"
        p12_file = paths.pkcs12 / f"{r_alias}.p12"

        crt_str = "YES" if crt_file.exists() else "NO"
        p12_str = "YES" if p12_file.exists() else "NO"

        days_str = "N/A"
        if crt_file.exists():
            cert = load_or_create_robot_certificate(robot, root_ca, config, paths)
            days_rem = days_until_expiration(cert.certificate)
            days_str = f"{days_rem} days"

        print(f"{robot.id:<8} {r_alias:<18} {r_host:<22} {crt_str:<6} {p12_str:<6} {days_str:<15}")

    print("-" * 85)


def verify_pki_command(config: FleetConfig, paths: ProjectPaths) -> bool:
    """
    Cryptographically verifies the Root CA and all fleet certificates.
    Returns True if all checks pass, False otherwise.
    """
    print_header("Verifying PKI Integrity")

    if not (paths.ca_key.exists() and paths.ca_certificate.exists()):
        print_warning("Verification failed: Root CA files do not exist.")
        return False

    root_ca = load_or_create_root_ca(config, paths)
    ca_ok, ca_msg = verify_root_ca(root_ca)
    if not ca_ok:
        print_warning(f"Root CA failed verification: {ca_msg}")
        return False
    print_success("Root CA verified successfully.")

    robots = list(expand_patterns(config.robots))
    errors = 0

    for robot in robots:
        cert = load_or_create_robot_certificate(robot, root_ca, config, paths)
        ok, msg = verify_robot_certificate(cert, root_ca)
        r_alias = alias(robot, config.server)

        if ok:
            print_success(f"{r_alias}: {msg}")
        else:
            print_warning(f"{r_alias}: FAILED - {msg}")
            errors += 1

    if errors == 0:
        print_header("Verification Result: ALL PASSED")
        return True
    else:
        print_header(f"Verification Result: {errors} FAILURE(S)")
        return False
