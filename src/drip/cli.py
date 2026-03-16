from __future__ import annotations

import argparse
import base64
import hashlib
import json
import os
import subprocess
import sys
import tempfile
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

DEFAULT_HOME = Path(".drip")


@dataclass
class DripPaths:
    home: Path
    keys: Path
    proofs: Path


class DripError(Exception):
    pass


def run_openssl(args: list[str], *, input_bytes: bytes | None = None) -> subprocess.CompletedProcess[bytes]:
    try:
        return subprocess.run(
            ["openssl", *args],
            input=input_bytes,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=True,
        )
    except FileNotFoundError as exc:
        raise DripError("openssl is required but not installed") from exc
    except subprocess.CalledProcessError as exc:
        message = exc.stderr.decode("utf-8", errors="replace").strip()
        raise DripError(f"openssl command failed: {' '.join(args)}\n{message}") from exc


def resolve_paths(home: str | None) -> DripPaths:
    root = Path(home).expanduser().resolve() if home else DEFAULT_HOME.resolve()
    return DripPaths(home=root, keys=root / "keys", proofs=root / "proofs")


def ensure_layout(paths: DripPaths) -> None:
    paths.home.mkdir(parents=True, exist_ok=True)
    paths.keys.mkdir(parents=True, exist_ok=True)
    paths.proofs.mkdir(parents=True, exist_ok=True)


def identity_private_key(paths: DripPaths, name: str) -> Path:
    return paths.keys / f"{name}.private.pem"


def identity_public_key(paths: DripPaths, name: str) -> Path:
    return paths.keys / f"{name}.public.pem"


def read_text(path: Path) -> str:
    return path.read_text(encoding="utf-8")


def sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        while True:
            block = f.read(64 * 1024)
            if not block:
                break
            h.update(block)
    return h.hexdigest()


def canonical_json_bytes(data: dict[str, Any]) -> bytes:
    return json.dumps(data, sort_keys=True, separators=(",", ":")).encode("utf-8")


def write_json(path: Path, data: dict[str, Any]) -> None:
    path.write_text(json.dumps(data, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def cmd_init(args: argparse.Namespace) -> int:
    paths = resolve_paths(args.home)
    ensure_layout(paths)
    print(f"Initialized DRIP home at {paths.home}")
    return 0


def cmd_identity_create(args: argparse.Namespace) -> int:
    paths = resolve_paths(args.home)
    ensure_layout(paths)
    private_key = identity_private_key(paths, args.name)
    public_key = identity_public_key(paths, args.name)

    if private_key.exists() or public_key.exists():
        raise DripError(f"identity '{args.name}' already exists")

    run_openssl(["genpkey", "-algorithm", "EC", "-pkeyopt", "ec_paramgen_curve:prime256v1", "-out", str(private_key)])
    run_openssl(["pkey", "-in", str(private_key), "-pubout", "-out", str(public_key)])

    print(f"Created identity '{args.name}'")
    print(f"Private key: {private_key}")
    print(f"Public key:  {public_key}")
    return 0


def cmd_identity_show(args: argparse.Namespace) -> int:
    paths = resolve_paths(args.home)
    public_key = identity_public_key(paths, args.name)
    if not public_key.exists():
        raise DripError(f"identity '{args.name}' not found")

    key_pem = read_text(public_key)
    did_seed = hashlib.sha256(key_pem.encode("utf-8")).hexdigest()[:32]
    did = f"did:drip:local:{did_seed}"

    result = {
        "name": args.name,
        "did": did,
        "publicKeyPath": str(public_key),
        "publicKeyPem": key_pem,
    }
    print(json.dumps(result, indent=2))
    return 0


def build_payload(*, file_path: Path, artifact_type: str, signer_did: str) -> dict[str, Any]:
    return {
        "version": 1,
        "artifactType": artifact_type,
        "hashAlg": "sha256",
        "digest": sha256_file(file_path),
        "signerDid": signer_did,
        "createdAt": datetime.now(tz=timezone.utc).isoformat().replace("+00:00", "Z"),
        "sourcePath": file_path.name,
    }


def sign_bytes(private_key_path: Path, data: bytes) -> bytes:
    with tempfile.NamedTemporaryFile(delete=False) as payload_file, tempfile.NamedTemporaryFile(delete=False) as sig_file:
        payload_file.write(data)
        payload_file.flush()
        payload_name = payload_file.name
        sig_name = sig_file.name
    try:
        run_openssl(["dgst", "-sha256", "-sign", str(private_key_path), "-out", sig_name, payload_name])
        return Path(sig_name).read_bytes()
    finally:
        for name in (payload_name, sig_name):
            try:
                os.unlink(name)
            except OSError:
                pass


def verify_bytes(public_key_path: Path, data: bytes, signature: bytes) -> bool:
    with tempfile.NamedTemporaryFile(delete=False) as payload_file, tempfile.NamedTemporaryFile(delete=False) as sig_file:
        payload_file.write(data)
        payload_file.flush()
        payload_name = payload_file.name
        sig_file.write(signature)
        sig_file.flush()
        sig_name = sig_file.name
    try:
        proc = subprocess.run(
            ["openssl", "dgst", "-sha256", "-verify", str(public_key_path), "-signature", sig_name, payload_name],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
        return proc.returncode == 0
    finally:
        for name in (payload_name, sig_name):
            try:
                os.unlink(name)
            except OSError:
                pass


def cmd_sign_file(args: argparse.Namespace) -> int:
    paths = resolve_paths(args.home)
    ensure_layout(paths)
    private_key = identity_private_key(paths, args.identity)
    public_key = identity_public_key(paths, args.identity)

    if not private_key.exists() or not public_key.exists():
        raise DripError(f"identity '{args.identity}' not found")

    file_path = Path(args.file).resolve()
    if not file_path.exists() or not file_path.is_file():
        raise DripError(f"file not found: {file_path}")

    key_pem = read_text(public_key)
    did = f"did:drip:local:{hashlib.sha256(key_pem.encode('utf-8')).hexdigest()[:32]}"

    payload = build_payload(file_path=file_path, artifact_type=args.artifact_type, signer_did=did)
    canonical_payload = canonical_json_bytes(payload)
    signature = sign_bytes(private_key, canonical_payload)

    proof = {
        "proofVersion": 1,
        "payload": payload,
        "canonicalPayload": canonical_payload.decode("utf-8"),
        "payloadHash": hashlib.sha256(canonical_payload).hexdigest(),
        "signature": {
            "alg": "ecdsa-p256-sha256",
            "encoding": "base64",
            "value": base64.b64encode(signature).decode("ascii"),
        },
        "publicKeyPem": key_pem,
    }

    if args.out:
        out_path = Path(args.out).resolve()
    else:
        out_path = (paths.proofs / f"{file_path.stem}.proof.json").resolve()
    write_json(out_path, proof)

    print(f"Signed {file_path}")
    print(f"Proof: {out_path}")
    return 0


def cmd_verify_file(args: argparse.Namespace) -> int:
    file_path = Path(args.file).resolve()
    proof_path = Path(args.proof).resolve()

    if not file_path.exists() or not file_path.is_file():
        raise DripError(f"file not found: {file_path}")
    if not proof_path.exists() or not proof_path.is_file():
        raise DripError(f"proof not found: {proof_path}")

    proof = json.loads(proof_path.read_text(encoding="utf-8"))
    payload = proof.get("payload")
    if not isinstance(payload, dict):
        raise DripError("invalid proof: missing payload object")

    expected_digest = payload.get("digest")
    actual_digest = sha256_file(file_path)
    digest_ok = expected_digest == actual_digest

    canonical_payload = canonical_json_bytes(payload)
    payload_hash = hashlib.sha256(canonical_payload).hexdigest()
    hash_ok = payload_hash == proof.get("payloadHash")

    sig_data = proof.get("signature", {})
    sig_value = sig_data.get("value")
    if not isinstance(sig_value, str):
        raise DripError("invalid proof: missing signature value")
    signature = base64.b64decode(sig_value)

    pub_pem = proof.get("publicKeyPem")
    if not isinstance(pub_pem, str):
        raise DripError("invalid proof: missing publicKeyPem")

    with tempfile.NamedTemporaryFile(delete=False, suffix=".pem") as pub_file:
        pub_file.write(pub_pem.encode("utf-8"))
        pub_file.flush()
        pub_name = pub_file.name
    try:
        signature_ok = verify_bytes(Path(pub_name), canonical_payload, signature)
    finally:
        try:
            os.unlink(pub_name)
        except OSError:
            pass

    result = {
        "file": str(file_path),
        "proof": str(proof_path),
        "checks": {
            "digestMatches": digest_ok,
            "payloadHashMatches": hash_ok,
            "signatureValid": signature_ok,
        },
        "verified": digest_ok and hash_ok and signature_ok,
    }

    print(json.dumps(result, indent=2))
    return 0 if result["verified"] else 1


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="drip", description="DRIP MVP CLI")
    parser.add_argument("--home", help="DRIP data directory (default: ./.drip)")

    sub = parser.add_subparsers(dest="command", required=True)

    p_init = sub.add_parser("init", help="Initialize DRIP local state")
    p_init.set_defaults(func=cmd_init)

    p_identity = sub.add_parser("identity", help="Identity commands")
    identity_sub = p_identity.add_subparsers(dest="identity_command", required=True)

    p_identity_create = identity_sub.add_parser("create", help="Create local identity keypair")
    p_identity_create.add_argument("name", nargs="?", default="default")
    p_identity_create.set_defaults(func=cmd_identity_create)

    p_identity_show = identity_sub.add_parser("show", help="Show identity DID and public key")
    p_identity_show.add_argument("name", nargs="?", default="default")
    p_identity_show.set_defaults(func=cmd_identity_show)

    p_sign = sub.add_parser("sign-file", help="Sign a file and emit a proof bundle")
    p_sign.add_argument("file")
    p_sign.add_argument("--identity", default="default")
    p_sign.add_argument("--artifact-type", default="generic-file")
    p_sign.add_argument("--out", help="Output proof path (defaults to .drip/proofs/<file>.proof.json)")
    p_sign.set_defaults(func=cmd_sign_file)

    p_verify = sub.add_parser("verify-file", help="Verify file against proof bundle")
    p_verify.add_argument("file")
    p_verify.add_argument("--proof", required=True)
    p_verify.set_defaults(func=cmd_verify_file)

    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    try:
        return int(args.func(args))
    except DripError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
