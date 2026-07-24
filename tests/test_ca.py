from pathlib import Path

from pki.ca import load_or_create_root_ca
from pki.config import load_config
from pki.models import ProjectPaths


def test_root_ca_creation(tmp_path: Path):

    cfg = tmp_path / "fleet.yml"

    cfg.write_text(
"""
ca:
  common_name: Test Root
  organization: Test Org
  country: ES

server:
  prefix: robobo-
  suffix: .local
  port: 44304

keystore:
  filename: robots.p12

robots: []
""",
encoding="utf8"
    )

    config = load_config(cfg)

    paths = ProjectPaths(tmp_path)

    paths.ensure_directories()

    root = load_or_create_root_ca(
        config,
        paths,
    )

    assert paths.ca_key.exists()
    assert paths.ca_certificate.exists()

    assert root.certificate.subject == root.certificate.issuer