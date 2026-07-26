"""
cli.py

Command-line interface entry point for Robobo PKI.
Supports subcommands: init-ca, generate, rebuild-keystore, list, verify.
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

from pki.config import load_config
from pki.generator import (
    generate_pki,
    init_ca_command,
    list_fleet_command,
    rebuild_keystores_command,
    verify_pki_command,
)
from pki.models import ProjectPaths


def build_parser() -> argparse.ArgumentParser:
    parent_parser = argparse.ArgumentParser(add_help=False)
    parent_parser.add_argument(
        "-c", "--config",
        type=Path,
        default=Path("fleet.yml"),
        help="Path to fleet configuration YAML file (default: fleet.yml)",
    )
    parent_parser.add_argument(
        "-r", "--root",
        type=Path,
        default=Path("."),
        help="Root project directory for output artifacts (default: current directory)",
    )

    parser = argparse.ArgumentParser(
        prog="generate_pki",
        description="Robobo PKI Generator - Manage Root CA and fleet SSL/TLS certificates.",
        parents=[parent_parser],
    )

    subparsers = parser.add_subparsers(dest="command", help="Available subcommands")

    subparsers.add_parser("init-ca", help="Initialize or load the Root CA", parents=[parent_parser])
    gen_parser = subparsers.add_parser("generate", help="Generate Root CA, fleet certificates, keystores, and manifest", parents=[parent_parser])
    gen_parser.add_argument("--force-robots", action="store_true", help="Re-sign/regenerate all robot certificates while preserving the existing Root CA")
    gen_parser.add_argument("--force-ca", action="store_true", help="Force regenerate Root CA certificate and key")
    gen_parser.add_argument("-f", "--force", action="store_true", help="Force regenerate Root CA and all robot certificates")

    subparsers.add_parser("rebuild-keystore", help="Rebuild PKCS#12 keystores and manifest from existing files", parents=[parent_parser])
    subparsers.add_parser("list", help="List fleet identities, certificates, and status", parents=[parent_parser])
    subparsers.add_parser("verify", help="Cryptographically verify Root CA and robot certificates", parents=[parent_parser])

    return parser


def main(args: list[str] | None = None) -> None:
    parser = build_parser()
    parsed = parser.parse_args(args)

    config_path: Path = parsed.config
    if not config_path.exists():
        print(f"Error: Config file '{config_path}' not found.", file=sys.stderr)
        sys.exit(1)

    config = load_config(config_path)
    paths = ProjectPaths(root=parsed.root)

    cmd = parsed.command or "generate"

    if cmd == "init-ca":
        init_ca_command(config, paths)
    elif cmd == "generate":
        generate_pki(
            config,
            paths,
            force=getattr(parsed, "force", False),
            force_ca=getattr(parsed, "force_ca", False),
            force_robots=getattr(parsed, "force_robots", False),
        )
    elif cmd == "rebuild-keystore":
        rebuild_keystores_command(config, paths)
    elif cmd == "list":
        list_fleet_command(config, paths)
    elif cmd == "verify":
        success = verify_pki_command(config, paths)
        if not success:
            sys.exit(1)
    else:
        parser.print_help()


if __name__ == "__main__":
    main()
