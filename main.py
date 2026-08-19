import argparse
import getpass
import hashlib
import hmac
import json
import os
import re
import socket
import sys
from collections import Counter, defaultdict
from dataclasses import dataclass, asdict
from datetime import datetime, timezone
from html.parser import HTMLParser
from pathlib import Path
from typing import Dict, Iterable, List, Optional, Tuple
from urllib.parse import unquote, urlparse
from urllib.request import Request, urlopen


APP_NAME = "EncryptVault CyberSuite"
VAULT_EXTENSION = ".nik"
BASELINE_FILE = ".encryptvault_fim_baseline.json"
SOC_EVENTS_FILE = "soc_events.jsonl"

ASCII_ART = r"""
 _____                            _ __     __          _ _
| ____|_ __   ___ _ __ _   _ _ __ | |\ \   / /_ _ _   _| | |_
|  _| | '_ \ / __| '__| | | | '_ \| __\ \ / / _` | | | | | __|
| |___| | | | (__| |  | |_| | |_) | |_ \ V / (_| | |_| | | |_
|_____|_| |_|\___|_|   \__, | .__/ \__| \_/ \__,_|\__,_|_|\__|
                       |___/|_|
"""


@dataclass
class Finding:
    module: str
    severity: str
    title: str
    detail: str
    target: str = ""

    def to_event(self) -> Dict[str, str]:
        data = asdict(self)
        data["timestamp"] = datetime.now(timezone.utc).isoformat()
        return data


class LinkAndFormParser(HTMLParser):
    def __init__(self):
        super().__init__()
        self.links: List[str] = []
        self.forms: List[Dict[str, str]] = []
        self._current_form: Optional[Dict[str, str]] = None

    def handle_starttag(self, tag, attrs):
        attrs_dict = dict(attrs)
        if tag == "a" and attrs_dict.get("href"):
            self.links.append(attrs_dict["href"])
        if tag == "form":
            self._current_form = {
                "action": attrs_dict.get("action", ""),
                "method": attrs_dict.get("method", "get").lower(),
                "inputs": "",
            }
        if tag == "input" and self._current_form is not None:
            name = attrs_dict.get("name") or attrs_dict.get("id") or "unnamed"
            self._current_form["inputs"] += f" {name}"

    def handle_endtag(self, tag):
        if tag == "form" and self._current_form is not None:
            self.forms.append(self._current_form)
            self._current_form = None


def load_crypto():
    from cryptography.hazmat.backends import default_backend
    from cryptography.hazmat.primitives import padding
    from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
    from cryptography.hazmat.primitives.kdf.scrypt import Scrypt

    return Cipher, algorithms, modes, Scrypt, padding, default_backend


def derive_key(password: str, salt: bytes) -> bytes:
    _, _, _, Scrypt, _, default_backend = load_crypto()
    kdf = Scrypt(salt=salt, length=32, n=2**14, r=8, p=1, backend=default_backend())
    return kdf.derive(password.encode())


def encrypt_data(data: bytes, password: str) -> bytes:
    Cipher, algorithms, modes, _, padding, default_backend = load_crypto()
    salt = os.urandom(16)
    key = derive_key(password, salt)
    iv = os.urandom(16)
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    padder = padding.PKCS7(128).padder()
    padded_data = padder.update(data) + padder.finalize()
    return salt + iv + encryptor.update(padded_data) + encryptor.finalize()


def decrypt_data(encrypted_data: bytes, password: str) -> bytes:
    Cipher, algorithms, modes, _, padding, default_backend = load_crypto()
    salt = encrypted_data[:16]
    iv = encrypted_data[16:32]
    key = derive_key(password, salt)
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    decryptor = cipher.decryptor()
    padded_data = decryptor.update(encrypted_data[32:]) + decryptor.finalize()
    unpadder = padding.PKCS7(128).unpadder()
    return unpadder.update(padded_data) + unpadder.finalize()


def generate_sha512_hash(file_path: str) -> str:
    sha512 = hashlib.sha512()
    with open(file_path, "rb") as f:
        for chunk in iter(lambda: f.read(8192), b""):
            sha512.update(chunk)
    return sha512.hexdigest()


def encrypt_file(file_path: str, password: str, keep_original: bool = False) -> Path:
    source = Path(file_path)
    encrypted_path = source.with_name(source.name + VAULT_EXTENSION)
    encrypted_path.write_bytes(encrypt_data(source.read_bytes(), password))
    if not keep_original:
        source.unlink()
    return encrypted_path


def decrypt_file(file_path: str, password: str, keep_original: bool = False) -> Path:
    source = Path(file_path)
    if source.name.endswith(VAULT_EXTENSION):
        decrypted_path = source.with_name(source.name[: -len(VAULT_EXTENSION)])
    else:
        decrypted_path = source.with_suffix(source.suffix + ".decrypted")
    decrypted_path.write_bytes(decrypt_data(source.read_bytes(), password))
    if not keep_original:
        source.unlink()
    return decrypted_path


def iter_files(path: Path) -> Iterable[Path]:
    if path.is_file():
        yield path
    else:
        for root, _, files in os.walk(path):
            for name in files:
                yield Path(root) / name


def vault_command(args):
    password = args.password or getpass.getpass("Password: ")
    target = Path(args.target)
    if args.action == "encrypt":
        for file_path in iter_files(target):
            if file_path.name.endswith(VAULT_EXTENSION):
                continue
            encrypted = encrypt_file(str(file_path), password, args.keep_original)
            print(f"Encrypted {file_path} -> {encrypted} sha512={generate_sha512_hash(str(encrypted))}")
    else:
        for file_path in iter_files(target):
            if target.is_dir() and not file_path.name.endswith(VAULT_EXTENSION):
                continue
            decrypted = decrypt_file(str(file_path), password, args.keep_original)
            print(f"Decrypted {file_path} -> {decrypted}")


def fetch_url(url: str, timeout: int = 8) -> Tuple[str, Dict[str, str]]:
    req = Request(url, headers={"User-Agent": f"{APP_NAME}/1.0"})
    with urlopen(req, timeout=timeout) as response:
        body = response.read(512_000).decode("utf-8", errors="ignore")
        return body, dict(response.headers)


def web_scan_command(args) -> List[Finding]:
    findings: List[Finding] = []
    body, headers = fetch_url(args.url)
    parser = LinkAndFormParser()
    parser.feed(body)
    security_headers = ["content-security-policy", "x-frame-options", "x-content-type-options", "strict-transport-security"]
    lower_headers = {k.lower(): v for k, v in headers.items()}
    for header in security_headers:
        if header not in lower_headers:
            findings.append(Finding("web-scan", "medium", "Missing security header", header, args.url))
    for form in parser.forms:
        text = " ".join(form.values()).lower()
        if any(word in text for word in ["password", "token", "secret"]):
            parsed = urlparse(args.url)
            if parsed.scheme != "https":
                findings.append(Finding("web-scan", "high", "Sensitive form over non-HTTPS", json.dumps(form), args.url))
    if re.search(r"(sql syntax|mysql_fetch|ORA-\d+|stack trace|traceback)", body, re.I):
        findings.append(Finding("web-scan", "high", "Error disclosure pattern", "Page contains common verbose error text", args.url))
    print_findings(findings)
    return findings


def osint_command(args) -> List[Finding]:
    target = args.target
    findings = [Finding("osint", "info", "Target profile", f"normalized={target.lower()} length={len(target)}", target)]
    if "@" in target:
        domain = target.split("@", 1)[1]
        findings.append(Finding("osint", "info", "Email domain", domain, target))
        try:
            socket.getaddrinfo(domain, None)
            findings.append(Finding("osint", "low", "Domain resolves", domain, target))
        except socket.gaierror:
            findings.append(Finding("osint", "medium", "Domain does not resolve", domain, target))
    else:
        try:
            infos = socket.getaddrinfo(target, None)
            ips = sorted({info[4][0] for info in infos})
            findings.append(Finding("osint", "info", "Resolved IPs", ", ".join(ips), target))
        except socket.gaierror:
            findings.append(Finding("osint", "medium", "No DNS records found", target, target))
    print_findings(findings)
    return findings


def phishing_command(args) -> List[Finding]:
    url = args.url
    parsed = urlparse(url if "://" in url else "http://" + url)
    host = parsed.hostname or ""
    findings: List[Finding] = []
    if parsed.scheme != "https":
        findings.append(Finding("phishing", "medium", "URL is not HTTPS", parsed.scheme, url))
    if re.match(r"^\d+\.\d+\.\d+\.\d+$", host):
        findings.append(Finding("phishing", "high", "Host is a raw IP address", host, url))
    if len(host.split(".")) > 4 or host.count("-") > 3:
        findings.append(Finding("phishing", "medium", "Suspicious hostname complexity", host, url))
    decoded = unquote(url)
    if any(token in decoded.lower() for token in ["login", "verify", "update", "secure", "account", "password"]):
        findings.append(Finding("phishing", "low", "Social-engineering keyword", decoded, url))
    if "@" in parsed.netloc:
        findings.append(Finding("phishing", "high", "URL authority contains @", parsed.netloc, url))
    print_findings(findings or [Finding("phishing", "info", "No obvious phishing heuristics matched", host, url)])
    return findings


def fim_command(args) -> List[Finding]:
    root = Path(args.path)
    baseline = Path(args.baseline or root / BASELINE_FILE)
    current = {str(p.relative_to(root) if root.is_dir() else p.name): generate_sha512_hash(str(p)) for p in iter_files(root) if p.name != baseline.name}
    if args.init or not baseline.exists():
        baseline.write_text(json.dumps(current, indent=2, sort_keys=True))
        print(f"Baseline saved to {baseline} with {len(current)} files")
        return []
    previous = json.loads(baseline.read_text())
    findings = []
    for name in sorted(set(previous) | set(current)):
        if name not in previous:
            findings.append(Finding("fim", "medium", "New file", name, str(root)))
        elif name not in current:
            findings.append(Finding("fim", "high", "Deleted file", name, str(root)))
        elif not hmac.compare_digest(previous[name], current[name]):
            findings.append(Finding("fim", "high", "Modified file", name, str(root)))
    print_findings(findings or [Finding("fim", "info", "No integrity changes", str(root), str(root))])
    return findings


def password_command(args) -> List[Finding]:
    password = args.password or getpass.getpass("Password to evaluate: ")
    score = 0
    checks = {
        "length >= 12": len(password) >= 12,
        "lowercase": bool(re.search(r"[a-z]", password)),
        "uppercase": bool(re.search(r"[A-Z]", password)),
        "digit": bool(re.search(r"\d", password)),
        "symbol": bool(re.search(r"[^A-Za-z0-9]", password)),
    }
    score = sum(checks.values())
    entropy_bits = len(password) * (4 if score < 3 else 6)
    severity = "low" if score >= 4 and entropy_bits >= 72 else "medium" if score >= 3 else "high"
    findings = [Finding("password", severity, "Password strength simulation", f"score={score}/5 estimated_bits={entropy_bits} checks={checks}")]
    print_findings(findings)
    return findings


def nid_command(args) -> List[Finding]:
    path = Path(args.log)
    findings = []
    ip_counter = Counter()
    port_counter = Counter()
    for line in path.read_text(errors="ignore").splitlines():
        for ip in re.findall(r"\b(?:\d{1,3}\.){3}\d{1,3}\b", line):
            ip_counter[ip] += 1
        for port in re.findall(r"(?:port|dpt|spt)[=:\s]+(\d{1,5})", line, re.I):
            port_counter[port] += 1
        if re.search(r"(denied|failed|scan|nmap|exploit|malware|intrusion)", line, re.I):
            findings.append(Finding("nid", "medium", "Suspicious log keyword", line[:160], str(path)))
    for ip, count in ip_counter.items():
        if count >= args.threshold:
            findings.append(Finding("nid", "high", "Repeated IP activity", f"{ip} seen {count} times", str(path)))
    print_findings(findings or [Finding("nid", "info", "No intrusion heuristics matched", str(path), str(path))])
    return findings


def malware_command(args) -> List[Finding]:
    data = Path(args.file).read_bytes()
    text = data.decode("utf-8", errors="ignore")
    indicators = {
        "process execution": r"(subprocess|CreateProcess|ShellExecute|cmd\.exe|powershell)",
        "persistence": r"(Run\\|Startup|cron|systemd|schtasks)",
        "network callback": r"(https?://|socket|connect\()",
        "credential access": r"(password|token|credential|keylogger)",
        "encoded payload": r"(base64|FromBase64String|eval\()",
    }
    findings = [Finding("malware", "medium", name, "Matched static behavior heuristic", args.file) for name, pattern in indicators.items() if re.search(pattern, text, re.I)]
    findings.append(Finding("malware", "info", "File fingerprint", f"sha256={hashlib.sha256(data).hexdigest()} size={len(data)}", args.file))
    print_findings(findings)
    return findings


SECRET_PATTERNS = {
    "AWS access key": r"AKIA[0-9A-Z]{16}",
    "GitHub token": r"gh[pousr]_[A-Za-z0-9_]{20,}",
    "Private key": r"-----BEGIN (?:RSA |EC |OPENSSH |)PRIVATE KEY-----",
    "Generic assignment": r"(?i)(api[_-]?key|secret|token|password)\s*[=:]\s*['\"][^'\"]{8,}['\"]",
}


def secrets_command(args) -> List[Finding]:
    root = Path(args.path)
    findings = []
    for file_path in iter_files(root):
        if ".git" in file_path.parts or file_path.is_dir() or file_path.stat().st_size > args.max_size:
            continue
        text = file_path.read_text(errors="ignore")
        for name, pattern in SECRET_PATTERNS.items():
            for match in re.finditer(pattern, text):
                line_no = text[: match.start()].count("\n") + 1
                findings.append(Finding("secrets", "high", name, f"{file_path}:{line_no}", str(root)))
    print_findings(findings or [Finding("secrets", "info", "No secrets found", str(root), str(root))])
    return findings


def soc_command(args):
    events = []
    for log in args.logs or []:
        events.extend(nid_command(argparse.Namespace(log=log, threshold=args.threshold)))
    if args.secrets_path:
        events.extend(secrets_command(argparse.Namespace(path=args.secrets_path, max_size=1_000_000)))
    if args.fim_path:
        events.extend(fim_command(argparse.Namespace(path=args.fim_path, baseline=args.baseline, init=False)))
    out = Path(args.output)
    with out.open("a") as handle:
        for finding in events:
            handle.write(json.dumps(finding.to_event()) + "\n")
    print(f"SOC dashboard summary: {len(events)} events written to {out}")
    summarize_events(events)


def summarize_events(findings: List[Finding]):
    counts = defaultdict(int)
    for finding in findings:
        counts[(finding.module, finding.severity)] += 1
    print("\nModule/Severity Summary")
    print("-----------------------")
    for (module, severity), count in sorted(counts.items()):
        print(f"{module:12} {severity:8} {count}")


def print_findings(findings: List[Finding]):
    for finding in findings:
        print(f"[{finding.severity.upper():7}] {finding.module}: {finding.title} - {finding.detail}")


def build_parser():
    parser = argparse.ArgumentParser(description=f"{APP_NAME}: an educational blue-team mega project")
    sub = parser.add_subparsers(dest="command", required=True)

    vault = sub.add_parser("vault", help="Encrypt/decrypt files and folders")
    vault.add_argument("action", choices=["encrypt", "decrypt"])
    vault.add_argument("target")
    vault.add_argument("--password")
    vault.add_argument("--keep-original", action="store_true")
    vault.set_defaults(func=vault_command)

    web = sub.add_parser("web-scan", help="Passive web vulnerability scanner")
    web.add_argument("url")
    web.set_defaults(func=web_scan_command)

    osint = sub.add_parser("osint", help="Basic OSINT investigation")
    osint.add_argument("target")
    osint.set_defaults(func=osint_command)

    phishing = sub.add_parser("phishing", help="Phishing URL detector")
    phishing.add_argument("url")
    phishing.set_defaults(func=phishing_command)

    fim = sub.add_parser("fim", help="File integrity monitor")
    fim.add_argument("path")
    fim.add_argument("--baseline")
    fim.add_argument("--init", action="store_true")
    fim.set_defaults(func=fim_command)

    passwd = sub.add_parser("password", help="Password attack/strength simulator")
    passwd.add_argument("--password")
    passwd.set_defaults(func=password_command)

    nid = sub.add_parser("nid", help="Network intrusion detector for logs")
    nid.add_argument("log")
    nid.add_argument("--threshold", type=int, default=10)
    nid.set_defaults(func=nid_command)

    malware = sub.add_parser("malware", help="Static malware behavior analyzer")
    malware.add_argument("file")
    malware.set_defaults(func=malware_command)

    secrets = sub.add_parser("secrets", help="Secrets scanner for Git working trees")
    secrets.add_argument("path", nargs="?", default=".")
    secrets.add_argument("--max-size", type=int, default=1_000_000)
    secrets.set_defaults(func=secrets_command)

    soc = sub.add_parser("soc", help="Mini SOC dashboard aggregator")
    soc.add_argument("--logs", nargs="*")
    soc.add_argument("--secrets-path")
    soc.add_argument("--fim-path")
    soc.add_argument("--baseline")
    soc.add_argument("--threshold", type=int, default=10)
    soc.add_argument("--output", default=SOC_EVENTS_FILE)
    soc.set_defaults(func=soc_command)
    return parser


def legacy_prompt():
    action = input("Do you want to (E)ncrypt or (D)ecrypt? ").strip().upper()
    target = input("Enter the file or folder path: ").strip()
    password = getpass.getpass("Enter the password: ")
    args = argparse.Namespace(action="encrypt" if action == "E" else "decrypt", target=target, password=password, keep_original=False)
    vault_command(args)


def main():
    print(ASCII_ART)
    if len(sys.argv) == 1:
        legacy_prompt()
        return
    parser = build_parser()
    args = parser.parse_args()
    args.func(args)


if __name__ == "__main__":
    main()
