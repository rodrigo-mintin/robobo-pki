from pathlib import Path

from pki.config import load_config


def test_load_config(tmp_path: Path):

    cfg = tmp_path / "fleet.yml"

    cfg.write_text(
"""
ca:
  common_name: Test Root
  organization: OpenAI
  country: ES

certificates:
  validity_years: 10

server:
  prefix: robobo-
  suffix: .local
  port: 44304

keystore:
  filename: robots.p12

robots:
  - 7V*
""",
encoding="utf8"
    )

    config = load_config(cfg)

    assert config.ca.common_name == "Test Root"
    assert config.ca.organization == "OpenAI"
    assert config.ca.country == "ES"

    assert config.certificates.validity_years == 10

    assert config.server.prefix == "robobo-"
    assert config.server.suffix == ".local"
    assert config.server.port == 44304

    assert config.keystore.filename == "robots.p12"

    assert config.robots == ("7V*",)

def test_default_certificate_validity(tmp_path: Path):

    cfg = tmp_path / "fleet.yml"

    cfg.write_text(
"""
ca:
  common_name: Test Root
  organization: OpenAI
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

    assert config.certificates.validity_years == 50