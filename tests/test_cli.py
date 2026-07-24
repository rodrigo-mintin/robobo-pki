from pathlib import Path
from pki.cli import main


def test_cli_execution(tmp_path: Path):
    cfg = tmp_path / "fleet.yml"
    cfg.write_text(
        """
ca:
  common_name: CLI Test Root
  organization: CLI Test Org
  country: ES

server:
  prefix: robobo-
  suffix: .local
  port: 44304

keystore:
  filename: robots.p12

robots:
  - CLI1
""",
        encoding="utf-8",
    )

    main(["--config", str(cfg), "--root", str(tmp_path)])

    assert (tmp_path / "output" / "RoboboRootCA.crt").exists()
    assert (tmp_path / "output" / "manifest.json").exists()
    assert (tmp_path / "output" / "robots" / "robobo-cli1.crt").exists()


def test_cli_subcommands(tmp_path: Path):
    cfg = tmp_path / "fleet.yml"
    cfg.write_text(
        """
ca:
  common_name: Subcommand Test Root
  organization: CLI Org
  country: ES

server:
  prefix: robobo-
  suffix: .local
  port: 44304

keystore:
  filename: robots.p12

robots:
  - SUB1
""",
        encoding="utf-8",
    )

    # 1. init-ca
    main(["init-ca", "--config", str(cfg), "--root", str(tmp_path)])
    assert (tmp_path / "output" / "RoboboRootCA.crt").exists()

    # 2. generate
    main(["generate", "--config", str(cfg), "--root", str(tmp_path)])
    assert (tmp_path / "output" / "robots" / "robobo-sub1.crt").exists()
    assert (tmp_path / "output" / "pkcs12" / "robobo-sub1.p12").exists()
    assert (tmp_path / "output" / "robots.p12").exists()

    # 3. rebuild-keystore
    main(["rebuild-keystore", "--config", str(cfg), "--root", str(tmp_path)])
    assert (tmp_path / "output" / "robots.p12").exists()

    # 4. list
    main(["list", "--config", str(cfg), "--root", str(tmp_path)])

    # 5. verify
    main(["verify", "--config", str(cfg), "--root", str(tmp_path)])
