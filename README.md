# Robobo PKI Generator

An idempotent Python tool and infrastructure manager for generating, maintaining, and verifying Public Key Infrastructure (PKI) assets for fleets of **Robobo educational/research robots** (developed by *Universidad de A Coruña*).

It generates an EC SECP256R1 **Robobo Root Certificate Authority (RoboboRootCA)**, device SSL/TLS certificates, individual and combined PKCS#12 (`.p12`) keystores, BKS keystores (`robobo-certs.bks`), and JSON manifests for client devices (such as Android smartphones/tablets).

---

## 🚀 Features

- **Idempotent Operations**: Safely run and re-run commands without regenerating existing valid keys or certificates.
- **Flexible Pattern Expansion**: Specify robot fleet IDs using wildcards (`7V*`), numeric ranges (`R{001-120}`), and character sets (`[A-Z]`).
- **X.509 Certificate Generation**: SECP256R1 EC keys, SHA-256 signatures, Subject Alternative Names (SAN), and `SERVER_AUTH` extended key usage.
- **PKCS#12 & BKS Keystores**: Export individual `.p12` files per robot, combined `.p12` bundles, and a single BKS keystore (`robobo-certs.bks`) containing all fleet identity keys and Root CA certificates.
- **Cryptographic Verification**: Built-in verification engine checking self-signatures, CA trust chains, key pair matching, and validity windows.
- **Android Integration Suite**: Includes Java helper classes (`android/`) for importing BKS keystores and manifests into Android `SSLContext` / `KeyManagerFactory`.

---

## 📦 Requirements & Installation

- **Python**: 3.9 or higher
- **Dependencies**: Listed in `requirements.txt` (`cryptography`, `PyYAML`, `pytest`)

```bash
pip install -r requirements.txt
```

---

## ⚙️ Configuration (`fleet.yml`)

Configure your fleet settings in `fleet.yml`:

```yaml
ca:
  common_name: Robobo Root CA
  organization: Universidad de A Coruña
  country: ES
  years_valid: 50

certificates:
  validity_years: 50

server:
  prefix: rob-
  suffix: .local
  port: 44304

keystore:
  filename: robobo-identities.p12

robots:
  - 7V*
  - R{001-120}
```

---

## 🛠️ CLI Usage

`generate_pki.py` supports subcommands and accepts optional `-c/--config` and `-r/--root` parameters.

### 1. Initialize Root CA
Initializes or loads the Root CA key and certificate (`RoboboRootCA.key` and `RoboboRootCA.crt`):
```bash
python generate_pki.py init-ca
```

### 2. Generate Fleet PKI (Default)
Idempotently processes RoboboRootCA, robot certificates, PKCS#12 keystores, BKS keystores (`robobo-certs.bks`), and JSON manifest:
```bash
python generate_pki.py generate
# or simply
python generate_pki.py
```

### 3. Export / Build BKS Keystore
Merges all generated robot `.p12` identities into `robobo-certs.bks` (automatically downloading BouncyCastle provider if needed):
```bash
python generate_pki.py export-bks
```

### 4. List Fleet Status
Prints a summary table of all fleet identities, certificate presence, and `.p12` status:
```bash
python generate_pki.py list
```

### 5. Cryptographic Verification
Verifies Root CA self-signature, private key pairing, certificate validity dates, and CA signatures for all fleet identities:
```bash
python generate_pki.py verify
```

---

## 📂 Output Artifacts (`output/`)

Executing the PKI generator produces the following structure in `output/` (ignored by `.gitignore` to prevent committing sensitive keys):

```text
output/
├── RoboboRootCA.crt          # PEM Robobo Root CA certificate
├── RoboboRootCA.key          # PEM Robobo Root CA private key
├── robobo-certs.bks          # Combined BKS fleet keystore (for Android)
├── robobo-identities.p12     # Combined PKCS#12 fleet keystore
├── keystore_password.txt     # Keystore password (generated per execution)
├── manifest.json             # JSON manifest with fingerprints, URLs & metadata
├── robots/
│   ├── rob-7vh.crt           # Robot X.509 certificate
│   ├── rob-7vh.key           # Robot EC private key
│   └── ...
└── pkcs12/
    ├── rob-7vh.p12           # Individual robot PKCS#12 keystore
    └── ...
```

---

## 📱 Android Client Integration Guide

### 📦 What Needs to be Put in the Android App Project?

To establish mTLS / TLS connections to fleet robots from an Android app, copy the following assets and Java files into your Android project:

#### 1. Java Source Code (`android/` -> `com.robobo.pki`)
- **[RoboboManifest.java](file:///D:/RemoteWork/robobo-pki/android/RoboboManifest.java)**: Parses `manifest.json` and verifies key availability (`isRobotAvailable("7VH")`) in advance.
- **[SSLContextFactory.java](file:///D:/RemoteWork/robobo-pki/android/SSLContextFactory.java)**: Builds `SSLContext` from `robobo-certs.bks` and configures identity key selection.
- **[RoboboKeyManager.java](file:///D:/RemoteWork/robobo-pki/android/RoboboKeyManager.java)**: Custom `X509ExtendedKeyManager` selecting specific robot aliases during TLS handshakes.

#### 2. App Assets (Place in `res/raw/` or `assets/`)
- **`robobo-certs.bks`**: The BKS keystore containing all fleet keys & Root CA trust entries.
- **`manifest.json`**: The JSON manifest used for looking up robot hostnames, URLs, and availability.
- **`keystore_password.txt`** (or hardcode/pass the password string in code).

---

### ❓ Is Manual Root CA Installation Required?

#### Inside the Android App: **NO**
- **Manual OS-level Root CA installation is NOT required** for your app.
- `robobo-certs.bks` embeds the `RoboboRootCA` certificate as a trusted CA entry. When `SSLContextFactory.createSSLContextFromBks(...)` initializes the app's `SSLContext`, it initializes the `TrustManager` directly from the BKS keystore. The app automatically trusts all Robobo fleet robots securely out-of-the-box!

#### On Robobo Fleet Robots:
- Each robot server uses its issued certificate (`rob-<id>.crt`) and private key (`rob-<id>.key`), signed by `RoboboRootCA`.

#### Optional OS Browser Access:
- If developers want to open robot endpoints (`https://rob-7vh.local:44304`) directly in the Android System Browser (Chrome), they can optionally install `RoboboRootCA.crt` into Android OS settings (`Settings > Security > Encryption & Credentials > Install a Certificate > CA Certificate`).

---

## 🧪 Running Unit Tests

Run the full pytest suite:

```bash
pytest
```
