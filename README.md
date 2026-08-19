# EncryptVault CyberSuite

EncryptVault CyberSuite is an educational Python mega project that combines the original AES file vault with a collection of small defensive security tools. It is designed for safe labs, portfolio demos, and blue-team learning rather than offensive exploitation.

## Included Mini Projects

- **Mini SOC Dashboard**: Aggregates findings from log analysis, file integrity monitoring, and secrets scanning into JSONL events.
- **Web Vulnerability Scanner**: Performs passive checks for missing security headers, sensitive forms over HTTP, and common error disclosure patterns.
- **OSINT Investigation Tool**: Normalizes a target, resolves domains, and reports basic email/domain intelligence.
- **Phishing URL Detector**: Scores URLs with heuristics such as raw IP hosts, non-HTTPS links, suspicious keywords, and `@` authority tricks.
- **File Integrity Monitor**: Creates and compares SHA-512 file baselines for tamper detection.
- **Password Attack Simulator**: Estimates password strength using safe local complexity checks.
- **Network Intrusion Detector**: Parses logs for suspicious keywords, repeated IP activity, and port indicators.
- **Malware Behavior Analyzer**: Performs static behavior heuristics and SHA-256 fingerprinting for suspicious files.
- **Secrets Scanner for Git**: Searches working trees for common token, key, and credential patterns while skipping `.git` internals.
- **Encrypted File Vault**: Encrypts and decrypts files or folders using AES-CBC with Scrypt key derivation.

## Safety and Scope

This project intentionally uses passive or local analysis techniques. Do not scan systems, URLs, repositories, or logs unless you own them or have explicit permission.

## Prerequisites

- Python 3.9+
- `cryptography`

Install dependencies:

```bash
python3 -m pip install cryptography
```

## Quick Start

Show all commands:

```bash
python3 main.py --help
```

Encrypt a file or folder:

```bash
python3 main.py vault encrypt path/to/file.txt --password "change-me"
```

Decrypt a `.nik` file or folder of `.nik` files:

```bash
python3 main.py vault decrypt path/to/file.txt.nik --password "change-me"
```

Run the legacy interactive vault prompt:

```bash
python3 main.py
```

## Tool Examples

### Mini SOC Dashboard

```bash
python3 main.py soc --logs auth.log firewall.log --secrets-path . --fim-path . --output soc_events.jsonl
```

### Web Vulnerability Scanner

```bash
python3 main.py web-scan https://example.com
```

### OSINT Investigation Tool

```bash
python3 main.py osint example.com
python3 main.py osint analyst@example.com
```

### Phishing URL Detector

```bash
python3 main.py phishing "http://192.0.2.10/login/verify-account"
```

### File Integrity Monitor

Create a baseline:

```bash
python3 main.py fim ./important-files --init
```

Check for changes:

```bash
python3 main.py fim ./important-files
```

### Password Attack Simulator

```bash
python3 main.py password --password "CorrectHorseBatteryStaple!2026"
```

### Network Intrusion Detector

```bash
python3 main.py nid ./security.log --threshold 5
```

### Malware Behavior Analyzer

```bash
python3 main.py malware ./sample.bin
```

### Secrets Scanner for Git

```bash
python3 main.py secrets .
```

## Output

Each module prints severity-tagged findings in the terminal. The SOC command also appends machine-readable JSON lines to `soc_events.jsonl` by default.

Example finding:

```text
[HIGH   ] secrets: GitHub token - src/config.py:12
```

## Project Structure

```text
main.py          # All CLI modules and encryption functions
README.md        # Documentation and examples
EncryptVault.exe # Existing precompiled legacy executable
```

## Notes

- Encrypted files use the `.nik` extension.
- Use `--keep-original` with the vault command if you do not want source files deleted after encryption or decryption.
- Keep passwords safe. Encrypted data cannot be recovered if the password is lost.
- The scanners are heuristic-based and can produce false positives or false negatives.

## Disclaimer

This software is for education, authorized security testing, and defensive analysis only. The authors and contributors are not responsible for misuse.

## Developed By

- **Nikhil Kulkarni (Nik)**
- GitHub: [https://github.com/sftp-nik/](https://github.com/sftp-nik/)

## License

This project is licensed under the MIT License. See the LICENSE file for details.
