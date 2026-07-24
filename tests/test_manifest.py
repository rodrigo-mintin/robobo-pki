import json
from pathlib import Path

from pki.ca import load_or_create_root_ca
from pki.certificates import load_or_create_robot_certificate
from pki.config import load_config
from pki.manifest import generate_manifest
from pki.models import Fleet, ProjectPaths, RobotIdentity


def test_generate_manifest(tmp_path: Path):
    cfg = tmp_path / "fleet.yml"
    cfg.write_text(
        """
ca:
  common_name: Test CA
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
        encoding="utf-8",
    )

    config = load_config(cfg)
    paths = ProjectPaths(tmp_path)
    paths.ensure_directories()

    root_ca = load_or_create_root_ca(config, paths)
    robot = RobotIdentity("7VH")
    cert = load_or_create_robot_certificate(robot, root_ca, config, paths)

    fleet = Fleet(root_ca=root_ca, certificates=[cert])

    manifest_file = generate_manifest(fleet, config, paths)

    assert manifest_file.exists()
    assert manifest_file == paths.manifest

    data = json.loads(manifest_file.read_text(encoding="utf-8"))

    assert data["ca"]["common_name"] == "Test CA"
    assert data["total_robots"] == 1
    assert len(data["robots"]) == 1
    assert data["robots"][0]["id"] == "7VH"
    assert data["robots"][0]["alias"] == "robobo-7vh"
    assert data["robots"][0]["hostname"] == "robobo-7vh.local"
