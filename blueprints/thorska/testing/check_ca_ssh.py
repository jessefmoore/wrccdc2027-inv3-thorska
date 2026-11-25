#!/usr/bin/env python3
"""Check Step CA SSH certificate issuance and login end to end.

The checker authenticates to the Flokie CA API with a shared API key and domain
credentials, requests a short-lived SSH user certificate, and uses that
certificate to run ``whoami`` on the target. Temporary private keys and
certificates are deleted when the check finishes.
"""

from __future__ import annotations

import argparse
import base64
import getpass
import json
import os
import shutil
import subprocess
import sys
import tempfile
import urllib.error
import urllib.request
from pathlib import Path


DEFAULT_API_URL = "http://10.100.203.231:8080"
DEFAULT_API_KEY = "SMBlyRequired!"


class CheckError(RuntimeError):
    """An expected scoring-check failure."""


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description=(
            "Request a Step SSH certificate using domain credentials and use "
            "it to test SSH certificate authentication on a target."
        )
    )
    parser.add_argument("target", help="Target hostname or IP address")
    parser.add_argument(
        "-u", "--username", required=True, help="Domain username used for API authentication"
    )
    parser.add_argument(
        "--password",
        help="Domain password; defaults to DOMAIN_PASSWORD or a hidden prompt",
    )
    parser.add_argument(
        "--principal",
        help=(
            "SSH certificate principal; defaults to the username without its "
            "domain component"
        ),
    )
    parser.add_argument(
        "--login-user",
        help="SSH login name; defaults to the certificate principal",
    )
    parser.add_argument("-p", "--port", type=int, default=22, help="SSH port (default: 22)")
    parser.add_argument(
        "--api-url",
        default=os.environ.get("STEP_CA_API_URL", DEFAULT_API_URL),
        help=f"CA API base URL (default: {DEFAULT_API_URL})",
    )
    parser.add_argument(
        "--api-key",
        default=os.environ.get("STEP_CA_API_KEY", DEFAULT_API_KEY),
        help="Shared API key; defaults to STEP_CA_API_KEY or the competition default",
    )
    parser.add_argument(
        "--duration", default="10m", help="Requested certificate duration (default: 10m)"
    )
    parser.add_argument(
        "--timeout", type=int, default=10, help="API and SSH timeout in seconds (default: 10)"
    )
    parser.add_argument(
        "--command", default="whoami", help="Harmless command executed after login"
    )
    parser.add_argument(
        "--keep-artifacts",
        action="store_true",
        help="Keep the temporary key and certificate files for troubleshooting",
    )
    return parser.parse_args()


def default_principal(username: str) -> str:
    """Convert alice@ice.land or ICE\alice to the usual Linux account name."""
    if "\\" in username:
        return username.rsplit("\\", 1)[1]
    if "@" in username:
        return username.split("@", 1)[0]
    return username


def require_executable(name: str) -> None:
    if shutil.which(name) is None:
        raise CheckError(f"required executable not found: {name}")


def run(command: list[str], timeout: int) -> subprocess.CompletedProcess[str]:
    try:
        return subprocess.run(
            command,
            check=False,
            capture_output=True,
            text=True,
            timeout=timeout,
        )
    except subprocess.TimeoutExpired as error:
        raise CheckError(f"command timed out after {timeout}s: {command[0]}") from error


def generate_keypair(private_key: Path, timeout: int) -> str:
    result = run(
        ["ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-f", str(private_key)],
        timeout,
    )
    if result.returncode != 0:
        raise CheckError(f"ssh-keygen failed: {result.stderr.strip()}")
    return private_key.with_suffix(".pub").read_text(encoding="utf-8").strip()


def request_certificate(
    *,
    api_url: str,
    api_key: str,
    username: str,
    password: str,
    public_key: str,
    principal: str,
    duration: str,
    timeout: int,
) -> str:
    endpoint = api_url.rstrip("/") + "/v1/certificates/ssh"
    body = json.dumps(
        {
            "key_id": f"scoring-{principal}",
            "public_key": public_key,
            "principals": [principal],
            "duration": duration,
        }
    ).encode("utf-8")
    basic = base64.b64encode(f"{username}:{password}".encode("utf-8")).decode("ascii")
    request = urllib.request.Request(
        endpoint,
        data=body,
        method="POST",
        headers={
            "Authorization": f"Basic {basic}",
            "Content-Type": "application/json",
            "X-API-Key": api_key,
        },
    )

    try:
        with urllib.request.urlopen(request, timeout=timeout) as response:
            response_body = response.read()
    except urllib.error.HTTPError as error:
        detail = error.read().decode("utf-8", errors="replace").strip()
        raise CheckError(f"CA API returned HTTP {error.code}: {detail}") from error
    except urllib.error.URLError as error:
        raise CheckError(f"could not reach CA API at {endpoint}: {error.reason}") from error

    try:
        payload = json.loads(response_body)
        certificate = payload["certificate"].strip()
    except (json.JSONDecodeError, KeyError, AttributeError) as error:
        raise CheckError("CA API response did not contain a valid SSH certificate") from error
    if not certificate.startswith("ssh-") or "-cert-v01@openssh.com" not in certificate:
        raise CheckError("CA API returned an unexpected certificate format")
    return certificate


def inspect_certificate(certificate_file: Path, timeout: int) -> str:
    result = run(["ssh-keygen", "-L", "-f", str(certificate_file)], timeout)
    if result.returncode != 0:
        raise CheckError(f"issued certificate is invalid: {result.stderr.strip()}")
    return result.stdout.strip()


def check_ssh_login(
    *,
    target: str,
    port: int,
    login_user: str,
    private_key: Path,
    certificate_file: Path,
    command: str,
    timeout: int,
) -> str:
    ssh_command = [
        "ssh",
        "-p",
        str(port),
        "-l",
        login_user,
        "-i",
        str(private_key),
        "-o",
        f"CertificateFile={certificate_file}",
        "-o",
        "IdentitiesOnly=yes",
        "-o",
        "BatchMode=yes",
        "-o",
        "PreferredAuthentications=publickey",
        "-o",
        "PasswordAuthentication=no",
        "-o",
        "KbdInteractiveAuthentication=no",
        "-o",
        "GSSAPIAuthentication=no",
        "-o",
        f"ConnectTimeout={timeout}",
        "-o",
        "StrictHostKeyChecking=no",
        "-o",
        "UserKnownHostsFile=/dev/null",
        "-o",
        "LogLevel=ERROR",
        target,
        command,
    ]
    result = run(ssh_command, timeout + 5)
    if result.returncode != 0:
        detail = result.stderr.strip() or result.stdout.strip() or f"exit status {result.returncode}"
        raise CheckError(f"SSH certificate login failed: {detail}")
    return result.stdout.strip()


def perform_check(args: argparse.Namespace, directory: Path) -> None:
    password = args.password or os.environ.get("DOMAIN_PASSWORD")
    if password is None:
        password = getpass.getpass(f"Domain password for {args.username}: ")
    if not password:
        raise CheckError("domain password cannot be empty")

    principal = args.principal or default_principal(args.username)
    login_user = args.login_user or principal
    if not principal or not login_user:
        raise CheckError("principal and login user cannot be empty")

    private_key = directory / "identity"
    certificate_file = directory / "identity-cert.pub"

    print(f"[1/4] Generating an ephemeral SSH keypair in {directory}", flush=True)
    public_key = generate_keypair(private_key, args.timeout)

    print(f"[2/4] Requesting an SSH certificate for principal {principal!r}", flush=True)
    certificate = request_certificate(
        api_url=args.api_url,
        api_key=args.api_key,
        username=args.username,
        password=password,
        public_key=public_key,
        principal=principal,
        duration=args.duration,
        timeout=args.timeout,
    )
    certificate_file.write_text(certificate + "\n", encoding="utf-8")
    certificate_file.chmod(0o600)

    print("[3/4] Validating the issued SSH certificate", flush=True)
    inspection = inspect_certificate(certificate_file, args.timeout)
    for line in inspection.splitlines():
        if "Valid:" in line or "Principals:" in line:
            print(f"      {line.strip()}")

    print(f"[4/4] Connecting to {login_user}@{args.target}:{args.port}", flush=True)
    output = check_ssh_login(
        target=args.target,
        port=args.port,
        login_user=login_user,
        private_key=private_key,
        certificate_file=certificate_file,
        command=args.command,
        timeout=args.timeout,
    )
    print(f"PASS: certificate login succeeded; command output: {output!r}")


def main() -> int:
    args = parse_args()
    try:
        require_executable("ssh-keygen")
        require_executable("ssh")
    except CheckError as error:
        print(f"FAIL: {error}", file=sys.stderr)
        return 1

    if args.keep_artifacts:
        directory = Path(tempfile.mkdtemp(prefix="ca-ssh-check-"))
        try:
            perform_check(args, directory)
        except CheckError as error:
            print(f"FAIL: {error}", file=sys.stderr)
            print(f"Artifacts kept in {directory}", file=sys.stderr)
            return 1
        print(f"Artifacts kept in {directory}")
        return 0

    try:
        with tempfile.TemporaryDirectory(prefix="ca-ssh-check-") as temporary_directory:
            perform_check(args, Path(temporary_directory))
    except CheckError as error:
        print(f"FAIL: {error}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
