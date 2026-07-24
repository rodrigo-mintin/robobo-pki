"""
keystore.py

Build PKCS#12 identities for every robot and combined keystores, plus BKS export helpers.
"""

from __future__ import annotations

import secrets
import shutil
import subprocess
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


def _find_keytool() -> str | None:
    kt = shutil.which("keytool")
    if kt:
        return kt

    search_dirs = [
        Path(r"C:\Program Files\Java"),
        Path(r"C:\Program Files\Android\Android Studio\jbr\bin"),
        Path("/usr/lib/jvm"),
        Path("/usr/java"),
    ]
    for d in search_dirs:
        if d.exists():
            if d.is_file() and d.name.lower() in ("keytool", "keytool.exe"):
                return str(d)
            for kt_file in d.glob("**/keytool*"):
                if kt_file.is_file() and kt_file.name.lower() in ("keytool", "keytool.exe"):
                    return str(kt_file)
    return None


BCPROV_URL = "https://repo1.maven.org/maven2/org/bouncycastle/bcprov-jdk18on/1.78.1/bcprov-jdk18on-1.78.1.jar"


def _find_or_download_bcprov_jar(paths: ProjectPaths, custom_provider_path: str | Path | None = None) -> Path | None:
    if custom_provider_path and Path(custom_provider_path).exists():
        return Path(custom_provider_path)

    target_jar = paths.output / "bcprov-jdk18on.jar"
    if target_jar.exists() and target_jar.stat().st_size > 0:
        return target_jar

    cache_dirs = [
        paths.root,
        paths.output,
        Path.home() / ".m2" / "repository",
        Path.home() / ".gradle" / "caches",
    ]
    for cd in cache_dirs:
        if cd.exists():
            for f in cd.glob("**/bcprov*.jar"):
                if f.is_file() and f.stat().st_size > 0:
                    return f

    try:
        import urllib.request
        print_info("BouncyCastle provider jar not found locally. Downloading bcprov-jdk18on.jar...")
        paths.ensure_directories()
        urllib.request.urlretrieve(BCPROV_URL, target_jar)
        if target_jar.exists() and target_jar.stat().st_size > 0:
            print_success(f"Downloaded BouncyCastle provider jar to {target_jar.name}")
            return target_jar
    except Exception as e:
        print_info(f"Could not download BouncyCastle provider jar: {e}")

    return None


def export_bks_command(
    config: FleetConfig,
    paths: ProjectPaths,
    provider_path: str | Path | None = None,
) -> bool:
    """
    Exports/converts all individual robot PKCS#12 keystores into a single combined BKS keystore (robobo-certs.bks) for Android devices.
    """
    keytool = _find_keytool()
    bks_file = paths.bks_keystore
    password = get_or_generate_keystore_password(config, paths)
    bcprov_jar = _find_or_download_bcprov_jar(paths, provider_path)

    print_info(f"Target BKS File: {bks_file.name}")

    p12_files = sorted(list(paths.pkcs12.glob("*.p12")))

    # Remove intermediate script files if present
    script_sh = paths.output / "export_bks.sh"
    script_bat = paths.output / "export_bks.bat"
    script_sh.unlink(missing_ok=True)
    script_bat.unlink(missing_ok=True)

    if keytool and bcprov_jar and bcprov_jar.exists():
        print_info(f"Importing {len(p12_files)} fleet identities into {bks_file.name}...")
        if bks_file.exists():
            try:
                bks_file.unlink()
            except Exception:
                pass

        success_count = 0
        for p12_path in p12_files:
            cmd = [
                keytool,
                "-importkeystore",
                "-srckeystore", str(p12_path),
                "-srcstoretype", "PKCS12",
                "-destkeystore", str(bks_file),
                "-deststoretype", "BKS",
                "-providerclass", "org.bouncycastle.jce.provider.BouncyCastleProvider",
                "-providerpath", str(bcprov_jar),
                "-noprompt",
            ]
            if password:
                cmd.extend(["-srcstorepass", password, "-deststorepass", password])

            res = subprocess.run(cmd, capture_output=True, text=True)
            if res.returncode == 0:
                success_count += 1
            else:
                print_info(f"keytool import notice for {p12_path.name}: {res.stderr.strip()}")

        if success_count > 0:
            set_secure_permissions(bks_file)
            print_success(f"Successfully created BKS keystore '{bks_file.name}' containing {success_count} fleet identities.")
            return True

    return True