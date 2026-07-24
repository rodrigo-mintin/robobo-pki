from pathlib import Path

from pki.config import load_config
from pki.generator import generate_pki
from pki.models import ProjectPaths


def test_generate_pki_end_to_end(tmp_path: Path):
    cfg = tmp_path / "fleet.yml"
    cfg.write_text(
        """
ca:
  common_name: Fleet CA
  organization: Fleet Org
  country: ES
  years_valid: 5

certificates:
  validity_years: 2

server:
  prefix: rob-
  suffix: .local
  port: 8443

keystore:
  filename: fleet-identities.p12
  password: secretpassword

robots:
  - T{001-002}
""",
        encoding="utf-8",
    )

    config = load_config(cfg)
    paths = ProjectPaths(tmp_path)

    fleet = generate_pki(config, paths)

    assert len(fleet.certificates) == 2
    assert paths.ca_key.exists()
    assert paths.ca_certificate.exists()
    assert paths.manifest.exists()
    assert (paths.robots / "rob-t001.crt").exists()
    assert (paths.robots / "rob-t001.key").exists()
    assert (paths.robots / "rob-t002.crt").exists()
    assert (paths.robots / "rob-t002.key").exists()
    assert (paths.pkcs12 / "rob-t001.p12").exists()
    assert (paths.pkcs12 / "rob-t002.p12").exists()
