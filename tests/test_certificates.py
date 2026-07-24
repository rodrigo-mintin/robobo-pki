from pathlib import Path

from pki.ca import load_or_create_root_ca
from pki.certificates import (
    days_until_expiration,
    load_or_create_robot_certificate,
    verify_robot_certificate,
)
from pki.config import load_config
from pki.models import ProjectPaths, RobotIdentity


def test_robot_certificate_lifecycle(tmp_path: Path):
    cfg_path = tmp_path / "fleet.yml"
    cfg_path.write_text(
        """
ca:
  common_name: Test Root
  organization: Test Org
  country: ES

server:
  prefix: robobo-
  suffix: .local
  port: 44304

certificates:
  validity_years: 10

keystore:
  filename: robots.p12

robots:
  - id: 7vh
""",
        encoding="utf8",
    )

    config = load_config(cfg_path)
    paths = ProjectPaths(tmp_path)
    paths.ensure_directories()

    root_ca = load_or_create_root_ca(config, paths)
    robot = RobotIdentity("7vh")

    # 1. Create certificate
    cert_obj = load_or_create_robot_certificate(robot, root_ca, config, paths)
    assert cert_obj.key_path.exists()
    assert cert_obj.certificate_path.exists()

    # 2. Verify certificate cryptographic validity
    is_valid, msg = verify_robot_certificate(cert_obj, root_ca)
    assert is_valid, f"Verification failed: {msg}"

    # 3. Check days until expiration
    days = days_until_expiration(cert_obj.certificate)
    assert days > 3000  # ~10 years

    # 4. Loading existing certificate without force
    loaded_cert_obj = load_or_create_robot_certificate(robot, root_ca, config, paths)
    assert loaded_cert_obj.certificate.serial_number == cert_obj.certificate.serial_number

    # 5. Force regeneration creates a new certificate with a new serial
    forced_cert_obj = load_or_create_robot_certificate(robot, root_ca, config, paths, force=True)
    assert forced_cert_obj.certificate.serial_number != cert_obj.certificate.serial_number
    is_valid_forced, msg_forced = verify_robot_certificate(forced_cert_obj, root_ca)
    assert is_valid_forced, f"Verification failed: {msg_forced}"
