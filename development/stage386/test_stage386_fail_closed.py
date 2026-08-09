#!/usr/bin/env python3

from __future__ import annotations

import hashlib
import json
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path


SOURCE_ROOT = Path(__file__).resolve().parents[2]


REQUIRED_FILES = [
    (
        "development/stage386/"
        "stage386_pqc_reverification_policy.json"
    ),
    (
        "development/stage386/"
        "verify_stage386_pqc_reverification.py"
    ),
    (
        "docs/mldsa-production/"
        "stage375_mldsa65_public_key.pem"
    ),
    (
        "docs/mldsa-production/"
        "stage375_mldsa65_signature.bin"
    ),
    (
        "docs/mldsa-production/"
        "stage375_mldsa65_execution_receipt.json"
    ),
    (
        "docs/final-acceptance-attestation/"
        "stage373_final_acceptance_attestation.json"
    ),
]


def run(
    args: list[str],
    cwd: Path,
) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        args,
        cwd=cwd,
        text=True,
        capture_output=True,
        check=False,
    )


def sha256_file(path: Path) -> str:
    return hashlib.sha256(
        path.read_bytes()
    ).hexdigest()


def build_workspace() -> Path:
    root = Path(
        tempfile.mkdtemp(
            prefix="qsp-stage386-test-"
        )
    )

    for relative in REQUIRED_FILES:
        source = SOURCE_ROOT / relative
        destination = root / relative

        destination.parent.mkdir(
            parents=True,
            exist_ok=True,
        )

        shutil.copy2(
            source,
            destination,
        )

    run(
        ["git", "init", "-q"],
        root,
    )

    run(
        [
            "git",
            "config",
            "user.email",
            "stage386-test@example.invalid",
        ],
        root,
    )

    run(
        [
            "git",
            "config",
            "user.name",
            "Stage386 Test",
        ],
        root,
    )

    run(
        ["git", "add", "."],
        root,
    )

    return root


def load_policy(root: Path) -> dict:
    path = (
        root
        / "development/stage386/"
        "stage386_pqc_reverification_policy.json"
    )

    return json.loads(
        path.read_text(encoding="utf-8")
    )


def save_policy(
    root: Path,
    policy: dict,
) -> None:
    path = (
        root
        / "development/stage386/"
        "stage386_pqc_reverification_policy.json"
    )

    path.write_text(
        json.dumps(
            policy,
            ensure_ascii=False,
            indent=2,
        )
        + "\n",
        encoding="utf-8",
    )

    run(
        ["git", "add", str(path.relative_to(root))],
        root,
    )


def execute(root: Path) -> tuple[int, dict]:
    verifier = (
        root
        / "development/stage386/"
        "verify_stage386_pqc_reverification.py"
    )

    proc = run(
        [sys.executable, str(verifier)],
        root,
    )

    result_path = (
        root
        / "development/stage386/"
        "stage386_pqc_independent_reverification_result.json"
    )

    if not result_path.is_file():
        raise RuntimeError(
            "Stage386 result was not generated.\n"
            + proc.stdout
            + proc.stderr
        )

    result = json.loads(
        result_path.read_text(
            encoding="utf-8"
        )
    )

    return proc.returncode, result


def assert_case(
    name: str,
    mutate,
    expected_decision: str,
    expected_exit: int,
) -> None:
    root = build_workspace()

    try:
        mutate(root)

        exit_code, result = execute(root)

        decision = result.get("decision")

        if (
            decision != expected_decision
            or exit_code != expected_exit
        ):
            raise AssertionError(
                f"{name}: "
                f"decision={decision!r}, "
                f"exit={exit_code}, "
                f"expected_decision="
                f"{expected_decision!r}, "
                f"expected_exit={expected_exit}"
            )

        print(
            f"PASS: {name} -> "
            f"{decision}"
        )

    finally:
        shutil.rmtree(
            root,
            ignore_errors=True,
        )


def no_change(root: Path) -> None:
    return None


def remove_public_key(root: Path) -> None:
    (
        root
        / "docs/mldsa-production/"
        "stage375_mldsa65_public_key.pem"
    ).unlink()


def alter_public_key_pem(root: Path) -> None:
    path = (
        root
        / "docs/mldsa-production/"
        "stage375_mldsa65_public_key.pem"
    )

    path.write_bytes(
        path.read_bytes() + b"\n"
    )


def force_der_expected_mismatch(
    root: Path,
) -> None:
    policy = load_policy(root)

    policy["expected"][
        "public_key_der_sha256"
    ] = "0" * 64

    save_policy(root, policy)


def remove_signature(root: Path) -> None:
    (
        root
        / "docs/mldsa-production/"
        "stage375_mldsa65_signature.bin"
    ).unlink()


def alter_signature(root: Path) -> None:
    path = (
        root
        / "docs/mldsa-production/"
        "stage375_mldsa65_signature.bin"
    )

    data = bytearray(path.read_bytes())
    data[0] ^= 0x01
    path.write_bytes(bytes(data))


def alter_target(root: Path) -> None:
    path = (
        root
        / "docs/final-acceptance-attestation/"
        "stage373_final_acceptance_attestation.json"
    )

    path.write_bytes(
        path.read_bytes() + b"\n"
    )


def alter_receipt(root: Path) -> None:
    path = (
        root
        / "docs/mldsa-production/"
        "stage375_mldsa65_execution_receipt.json"
    )

    data = json.loads(
        path.read_text(encoding="utf-8")
    )

    data["github_run_id"] = 0

    path.write_text(
        json.dumps(
            data,
            ensure_ascii=False,
            indent=2,
        )
        + "\n",
        encoding="utf-8",
    )


def alter_algorithm(root: Path) -> None:
    policy = load_policy(root)

    policy["algorithm"] = "ML-DSA-44"

    save_policy(root, policy)


def alter_context(root: Path) -> None:
    policy = load_policy(root)

    policy["context_string"] = (
        "QSP-Stage386-WRONG"
    )

    save_policy(root, policy)


def add_private_pem(root: Path) -> None:
    path = (
        root
        / "docs/"
        "stage386_fake_private.pem"
    )

    path.parent.mkdir(
        parents=True,
        exist_ok=True,
    )

    path.write_text(
        "-----BEGIN PRIVATE KEY-----\n"
        "TEST-ONLY-NOT-A-REAL-KEY\n"
        "-----END PRIVATE KEY-----\n",
        encoding="utf-8",
    )

    run(
        ["git", "add", str(path.relative_to(root))],
        root,
    )


def add_forbidden_tracked_path(
    root: Path,
) -> None:
    path = (
        root
        / "private/"
        "stage386-test-marker.txt"
    )

    path.parent.mkdir(
        parents=True,
        exist_ok=True,
    )

    path.write_text(
        "test-only\n",
        encoding="utf-8",
    )

    run(
        [
            "git",
            "add",
            "-f",
            str(path.relative_to(root)),
        ],
        root,
    )


def main() -> int:
    cases = [
        (
            "baseline succeeds",
            no_change,
            "pqc_independent_reverification_verified",
            0,
        ),
        (
            "public key missing",
            remove_public_key,
            "pqc_public_key_missing",
            1,
        ),
        (
            "PEM hash mismatch",
            alter_public_key_pem,
            "pqc_public_key_pem_hash_mismatch",
            1,
        ),
        (
            "DER hash mismatch",
            force_der_expected_mismatch,
            "pqc_public_key_der_hash_mismatch",
            1,
        ),
        (
            "signature missing",
            remove_signature,
            "pqc_signature_missing",
            1,
        ),
        (
            "signature tampering",
            alter_signature,
            "pqc_signature_hash_mismatch",
            1,
        ),
        (
            "signed target tampering",
            alter_target,
            "pqc_signed_target_hash_mismatch",
            1,
        ),
        (
            "Stage375 receipt mismatch",
            alter_receipt,
            "pqc_stage375_receipt_binding_mismatch",
            1,
        ),
        (
            "algorithm downgrade",
            alter_algorithm,
            "pqc_algorithm_identifier_mismatch",
            1,
        ),
        (
            "context mismatch",
            alter_context,
            "pqc_context_string_mismatch",
            1,
        ),
        (
            "private PEM publication",
            add_private_pem,
            "fail_closed",
            1,
        ),
        (
            "forbidden tracked path",
            add_forbidden_tracked_path,
            "fail_closed",
            1,
        ),
    ]

    for (
        name,
        mutate,
        expected_decision,
        expected_exit,
    ) in cases:
        assert_case(
            name,
            mutate,
            expected_decision,
            expected_exit,
        )

    print()
    print(
        "PASS: all Stage386 "
        "fail-closed tests completed"
    )

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
