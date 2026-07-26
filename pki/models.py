"""
models.py

Data models used throughout the Robobo PKI project.
"""

from dataclasses import dataclass
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec


# ============================================================================
# Robot identity
# ============================================================================

@dataclass(frozen=True, order=True)
class RobotIdentity:
    """
    Represents a single robot identity.

    Example
    -------
    ID:         7VH
    Hostname:   robobo-7vh.local
    Alias:      robobo-7vh
    """

    id: str

    def __post_init__(self):
        object.__setattr__(self, "id", self.id.upper())

    @property
    def alias(self) -> str:
        return f"robobo-{self.id.lower()}"

    @property
    def hostname(self) -> str:
        return f"{self.alias}.local"

    @property
    def certificate_filename(self) -> str:
        return f"{self.alias}.crt"

    @property
    def key_filename(self) -> str:
        return f"{self.alias}.key"

    @property
    def p12_alias(self) -> str:
        return self.alias


# ============================================================================
# Root Certificate Authority
# ============================================================================

@dataclass
class RootCA:
    """
    Represents the project's Root Certificate Authority.
    """

    private_key: ec.EllipticCurvePrivateKey

    certificate: x509.Certificate

    key_path: Path

    certificate_path: Path

    def sign(
        self,
        builder: x509.CertificateBuilder,
    ) -> x509.Certificate:
        """
        Signs a CertificateBuilder using this CA.
        """

        return builder.sign(
            private_key=self.private_key,
            algorithm=hashes.SHA256(),
        )

    def next_serial_number(self) -> int:
        """
        Returns a new RFC 5280-compliant serial number.
        """
        return x509.random_serial_number()

    def authority_key_identifier(
            self,
        ) -> x509.AuthorityKeyIdentifier:
            """
            Returns an AuthorityKeyIdentifier extension value
            derived from this CA.
            """

            return x509.AuthorityKeyIdentifier.from_issuer_public_key(
                self.public_key
            )

    @property
    def subject(self) -> x509.Name:
        return self.certificate.subject

    @property
    def issuer(self) -> x509.Name:
        return self.certificate.issuer

    @property
    def public_key(self):
        return self.certificate.public_key()

    @property
    def fingerprint(self) -> bytes:
        """
        Returns the SHA-256 fingerprint as raw bytes.
        """

        return self.certificate.fingerprint(
            hashes.SHA256()
        )


# ============================================================================
# Project paths
# ============================================================================

@dataclass(frozen=True)
class ProjectPaths:
    """
    Centralizes every filesystem path used by the project.

    Changing the output directory later only requires changing this class.
    """

    root: Path

    def __post_init__(self):
        if not isinstance(self.root, Path):
            object.__setattr__(self, "root", Path(self.root))

    @property
    def output(self) -> Path:
        return self.root / "output"

    @property
    def robots(self) -> Path:
        return self.output / "robots"

    @property
    def pkcs12(self) -> Path:
        return self.output / "pkcs12"

    @property
    def manifest(self) -> Path:
        return self.output / "manifest.json"

    @property
    def ca_key(self) -> Path:
        return self.output / "RoboboRootCA.key"

    @property
    def ca_certificate(self) -> Path:
        return self.output / "RoboboRootCA.crt"

    @property
    def keystore(self) -> Path:
        return self.output / "robobo-identities.p12"

    @property
    def keystore_password(self) -> Path:
        return self.output / "keystore_password.txt"

    def ensure_directories(self):
        """
        Creates every required directory.
        """

        self.output.mkdir(parents=True, exist_ok=True)
        self.robots.mkdir(parents=True, exist_ok=True)
        self.pkcs12.mkdir(parents=True, exist_ok=True)


@dataclass
class RobotCertificate:
    robot: RobotIdentity

    private_key: ec.EllipticCurvePrivateKey

    certificate: x509.Certificate

    key_path: Path

    certificate_path: Path

@dataclass
class Fleet:
    """
    Complete generated PKI.
    """

    root_ca: RootCA

    certificates: list[RobotCertificate]