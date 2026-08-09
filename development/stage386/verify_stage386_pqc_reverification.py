#!/usr/bin/env python3

from __future__ import annotations

import hashlib
import json
import subprocess
import sys
import tempfile
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]

POLICY_PATH = (
    ROOT
    / "development/stage386/"
    "stage386_pqc_reverification_policy.json"
)

RESULT_PATH = (
    ROOT
    / "development/stage386/"
    "stage386_pqc_independent_reverification_result.json"
)

RESULT_SHA_PATH = (
    ROOT
    / "development/stage386/"
    "stage386_pqc_independent_reverification_result.sha256"
)


PRIVATE_PEM_HEADERS = {
    b"-----BEGIN PRIVATE KEY-----",
    b"-----BEGIN RSA PRIVATE KEY-----",
    b"-----BEGIN EC PRIVATE KEY-----",
    b"-----BEGIN OPENSSH PRIVATE KEY-----",
}

FORBIDDEN_PATH_COMPONENTS = {
    "core",
    "private_core",
    "private",
    "secrets",
    "keys",
    "imported",
}


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def sha256_file(path: Path) -> str:
    return sha256_bytes(path.read_bytes())


def load_json(path: Path) -> dict:
    return json.loads(path.read_text(encoding="utf-8"))


def run(
    args: list[str],
    *,
    cwd: Path = ROOT,
) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        args,
        cwd=cwd,
        text=True,
        capture_output=True,
        check=False,
    )


def canonical_attestation_sha256(
    target_path: Path,
) -> tuple[str | None, str]:
    data = load_json(target_path)

    declared = data.get("attestation_sha256")

    canonical_data = dict(data)
    canonical_data.pop("attestation_sha256", None)

    canonical = json.dumps(
        canonical_data,
        ensure_ascii=False,
        sort_keys=True,
        indent=2,
    ).encode("utf-8")

    return (
        declared,
        sha256_bytes(canonical),
    )


def tracked_files() -> list[str]:
    proc = run(["git", "ls-files"])

    if proc.returncode != 0:
        raise RuntimeError(
            "git ls-files failed: "
            + proc.stderr.strip()
        )

    return [
        line.strip()
        for line in proc.stdout.splitlines()
        if line.strip()
    ]


def has_forbidden_tracked_path(
    files: list[str],
) -> tuple[bool, list[str]]:
    found: list[str] = []

    for name in files:
        parts = Path(name).parts

        if any(
            part in FORBIDDEN_PATH_COMPONENTS
            for part in parts
        ):
            found.append(name)

    return bool(found), found


def actual_private_pem_files(
    files: list[str],
) -> list[str]:
    found: list[str] = []

    for name in files:
        path = ROOT / name

        if not path.is_file():
            continue

        try:
            first_line = (
                path.open("rb")
                .readline()
                .strip()
            )
        except OSError:
            continue

        if first_line in PRIVATE_PEM_HEADERS:
            found.append(name)

    return found


def decision_from_checks(
    checks: dict[str, bool],
) -> str:
    ordered_failures = [
        (
            "public_key_present",
            "pqc_public_key_missing",
        ),
        (
            "public_key_pem_sha256_matches",
            "pqc_public_key_pem_hash_mismatch",
        ),
        (
            "public_key_der_sha256_matches",
            "pqc_public_key_der_hash_mismatch",
        ),
        (
            "signature_present",
            "pqc_signature_missing",
        ),
        (
            "signature_sha256_matches",
            "pqc_signature_hash_mismatch",
        ),
        (
            "signed_target_present",
            "pqc_signed_target_missing",
        ),
        (
            "signed_target_sha256_matches",
            "pqc_signed_target_hash_mismatch",
        ),
        (
            "logical_attestation_sha256_matches",
            "pqc_logical_attestation_hash_mismatch",
        ),
        (
            "receipt_binding_verified",
            "pqc_stage375_receipt_binding_mismatch",
        ),
        (
            "algorithm_identifier_verified",
            "pqc_algorithm_identifier_mismatch",
        ),
        (
            "context_string_verified",
            "pqc_context_string_mismatch",
        ),
        (
            "independent_mldsa65_verification",
            "pqc_independent_reverification_failed",
        ),
    ]

    for check_name, failure_decision in ordered_failures:
        if not checks.get(check_name, False):
            return failure_decision

    if not checks.get("no_forbidden_tracked_paths", False):
        return "fail_closed"

    if not checks.get("no_private_key_published", False):
        return "fail_closed"

    return "pqc_independent_reverification_verified"


def main() -> int:
    if not POLICY_PATH.is_file():
        print(
            "ERROR: Stage386 policy missing:",
            POLICY_PATH.relative_to(ROOT),
            file=sys.stderr,
        )
        return 2

    policy = load_json(POLICY_PATH)

    expected = policy["expected"]
    paths = policy["paths"]

    public_key = ROOT / paths["public_key"]
    signature = ROOT / paths["signature"]
    receipt_path = ROOT / paths["execution_receipt"]
    target = ROOT / paths["signed_target"]

    observations: dict[str, object] = {
        "public_key_pem_sha256": None,
        "public_key_der_sha256": None,
        "signature_sha256": None,
        "signed_target_sha256": None,
        "declared_attestation_sha256": None,
        "logical_attestation_sha256": None,
        "openssl_public_key_type": None,
        "openssl_verify_exit_code": None,
    }

    checks: dict[str, bool] = {}

    checks["public_key_present"] = (
        public_key.is_file()
        and public_key.stat().st_size > 0
    )

    if checks["public_key_present"]:
        observations[
            "public_key_pem_sha256"
        ] = sha256_file(public_key)

        checks[
            "public_key_pem_sha256_matches"
        ] = (
            observations["public_key_pem_sha256"]
            == expected["public_key_pem_sha256"]
        )
    else:
        checks[
            "public_key_pem_sha256_matches"
        ] = False

    checks["signature_present"] = (
        signature.is_file()
        and signature.stat().st_size > 0
    )

    if checks["signature_present"]:
        observations[
            "signature_sha256"
        ] = sha256_file(signature)

        checks[
            "signature_sha256_matches"
        ] = (
            observations["signature_sha256"]
            == expected["signature_sha256"]
        )
    else:
        checks[
            "signature_sha256_matches"
        ] = False

    checks["signed_target_present"] = (
        target.is_file()
        and target.stat().st_size > 0
    )

    if checks["signed_target_present"]:
        observations[
            "signed_target_sha256"
        ] = sha256_file(target)

        checks[
            "signed_target_sha256_matches"
        ] = (
            observations["signed_target_sha256"]
            == expected["signed_target_sha256"]
        )

        try:
            declared, logical = (
                canonical_attestation_sha256(
                    target
                )
            )
            observations[
                "declared_attestation_sha256"
            ] = declared
            observations[
                "logical_attestation_sha256"
            ] = logical

            checks[
                "logical_attestation_sha256_matches"
            ] = (
                declared
                == expected[
                    "logical_attestation_sha256"
                ]
                and logical
                == expected[
                    "logical_attestation_sha256"
                ]
            )
        except (
            OSError,
            UnicodeDecodeError,
            json.JSONDecodeError,
        ):
            checks[
                "logical_attestation_sha256_matches"
            ] = False
    else:
        checks[
            "signed_target_sha256_matches"
        ] = False
        checks[
            "logical_attestation_sha256_matches"
        ] = False

    checks["public_key_der_sha256_matches"] = False
    checks["algorithm_identifier_verified"] = False

    if checks["public_key_present"]:
        with tempfile.TemporaryDirectory(
            prefix="qsp-stage386-"
        ) as temp_dir:
            der_path = (
                Path(temp_dir)
                / "stage375_mldsa65_public_key.der"
            )

            der_proc = run(
                [
                    "openssl",
                    "pkey",
                    "-pubin",
                    "-in",
                    str(public_key),
                    "-outform",
                    "DER",
                    "-out",
                    str(der_path),
                ]
            )

            if (
                der_proc.returncode == 0
                and der_path.is_file()
            ):
                observations[
                    "public_key_der_sha256"
                ] = sha256_file(der_path)

                checks[
                    "public_key_der_sha256_matches"
                ] = (
                    observations[
                        "public_key_der_sha256"
                    ]
                    == expected[
                        "public_key_der_sha256"
                    ]
                )

        text_proc = run(
            [
                "openssl",
                "pkey",
                "-pubin",
                "-in",
                str(public_key),
                "-text",
                "-noout",
            ]
        )

        public_text = (
            text_proc.stdout
            + text_proc.stderr
        )

        first_line = (
            public_text.splitlines()[0]
            if public_text.splitlines()
            else ""
        )

        observations[
            "openssl_public_key_type"
        ] = first_line

        checks[
            "algorithm_identifier_verified"
        ] = (
            text_proc.returncode == 0
            and "ML-DSA-65" in public_text
            and policy.get("algorithm")
            == "ML-DSA-65"
        )

    checks["receipt_binding_verified"] = False
    checks["context_string_verified"] = False

    if receipt_path.is_file():
        try:
            receipt = load_json(receipt_path)

            checks[
                "receipt_binding_verified"
            ] = all(
                [
                    receipt.get("stage") == 375,
                    receipt.get("algorithm")
                    == "ML-DSA-65",
                    receipt.get(
                        "execution_status"
                    )
                    == "verified",
                    receipt.get(
                        "public_key_pem_sha256"
                    )
                    == expected[
                        "public_key_pem_sha256"
                    ],
                    receipt.get(
                        "public_key_der_sha256"
                    )
                    == expected[
                        "public_key_der_sha256"
                    ],
                    receipt.get(
                        "signature_sha256"
                    )
                    == expected[
                        "signature_sha256"
                    ],
                    receipt.get(
                        "target_blob_sha256"
                    )
                    == expected[
                        "signed_target_sha256"
                    ],
                    receipt.get(
                        "github_sha"
                    )
                    == expected[
                        "historical_stage375_github_sha"
                    ],
                    str(
                        receipt.get(
                            "github_run_id"
                        )
                    )
                    == str(
                        expected[
                            "historical_stage375_github_run_id"
                        ]
                    ),
                    receipt.get(
                        "private_key_published"
                    )
                    is False,
                ]
            )

            checks[
                "context_string_verified"
            ] = (
                receipt.get("context_string")
                == policy.get(
                    "context_string"
                )
                == "QSP-Stage375-v1"
            )

        except (
            OSError,
            UnicodeDecodeError,
            json.JSONDecodeError,
        ):
            pass

    checks[
        "independent_mldsa65_verification"
    ] = False

    if (
        checks["public_key_present"]
        and checks["signature_present"]
        and checks["signed_target_present"]
        and checks[
            "algorithm_identifier_verified"
        ]
    ):
        verify_proc = run(
            [
                "openssl",
                "pkeyutl",
                "-verify",
                "-in",
                str(target),
                "-pubin",
                "-inkey",
                str(public_key),
                "-sigfile",
                str(signature),
                "-pkeyopt",
                (
                    "context-string:"
                    + policy["context_string"]
                ),
            ]
        )

        observations[
            "openssl_verify_exit_code"
        ] = verify_proc.returncode

        checks[
            "independent_mldsa65_verification"
        ] = (
            verify_proc.returncode == 0
        )

    try:
        files = tracked_files()

        forbidden, forbidden_files = (
            has_forbidden_tracked_path(files)
        )

        private_pem_files = (
            actual_private_pem_files(files)
        )

        checks[
            "no_forbidden_tracked_paths"
        ] = not forbidden

        checks[
            "no_private_key_published"
        ] = not private_pem_files

    except RuntimeError:
        forbidden_files = []
        private_pem_files = []

        checks[
            "no_forbidden_tracked_paths"
        ] = False

        checks[
            "no_private_key_published"
        ] = False

    decision = decision_from_checks(checks)

    success = (
        decision
        == policy["success_decision"]
    )

    checks[
        "third_party_reverification_supported"
    ] = success

    result = {
        "stage": 386,
        "source_stage": 385,
        "engine": (
            "PQC Independent Re-verification, "
            "Public Key Binding & "
            "Evidence Portability Gate"
        ),
        "algorithm": "ML-DSA-65",
        "fips_standard": "FIPS 204",
        "context_string": (
            policy["context_string"]
        ),
        "decision": decision,
        "verification_status": (
            "verified"
            if success
            else "fail_closed_or_incomplete"
        ),
        "checks": checks,
        "observations": observations,
        "historical_binding": {
            "stage375_github_sha": (
                expected[
                    "historical_stage375_github_sha"
                ]
            ),
            "stage375_github_run_id": (
                expected[
                    "historical_stage375_github_run_id"
                ]
            ),
            "new_key_generated": False,
            "private_key_published": False,
        },
        "security_boundary": {
            "forbidden_tracked_paths": (
                forbidden_files
            ),
            "private_pem_files": (
                private_pem_files
            ),
        },
        "limitations": {
            "entire_system_quantum_safe": False,
            "fips_140_module_validation_claimed": False,
        },
    }

    result_text = (
        json.dumps(
            result,
            ensure_ascii=False,
            sort_keys=True,
            indent=2,
        )
        + "\n"
    )

    RESULT_PATH.write_text(
        result_text,
        encoding="utf-8",
    )

    result_sha = sha256_bytes(
        result_text.encode("utf-8")
    )

    RESULT_SHA_PATH.write_text(
        (
            result_sha
            + "  "
            + str(
                RESULT_PATH.relative_to(ROOT)
            )
            + "\n"
        ),
        encoding="utf-8",
    )

    print(
        "stage =",
        result["stage"],
    )
    print(
        "decision =",
        result["decision"],
    )
    print(
        "verification_status =",
        result["verification_status"],
    )
    print(
        "public_key_pem_sha256_matches =",
        checks.get(
            "public_key_pem_sha256_matches"
        ),
    )
    print(
        "public_key_der_sha256_matches =",
        checks.get(
            "public_key_der_sha256_matches"
        ),
    )
    print(
        "signature_sha256_matches =",
        checks.get(
            "signature_sha256_matches"
        ),
    )
    print(
        "signed_target_sha256_matches =",
        checks.get(
            "signed_target_sha256_matches"
        ),
    )
    print(
        "logical_attestation_sha256_matches =",
        checks.get(
            "logical_attestation_sha256_matches"
        ),
    )
    print(
        "receipt_binding_verified =",
        checks.get(
            "receipt_binding_verified"
        ),
    )
    print(
        "algorithm_identifier_verified =",
        checks.get(
            "algorithm_identifier_verified"
        ),
    )
    print(
        "context_string_verified =",
        checks.get(
            "context_string_verified"
        ),
    )
    print(
        "independent_mldsa65_verification =",
        checks.get(
            "independent_mldsa65_verification"
        ),
    )
    print(
        "third_party_reverification_supported =",
        checks.get(
            "third_party_reverification_supported"
        ),
    )
    print(
        "no_private_key_published =",
        checks.get(
            "no_private_key_published"
        ),
    )
    print(
        "entire_system_quantum_safe = False"
    )
    print(
        "result_sha256 =",
        result_sha,
    )

    return 0 if success else 1


if __name__ == "__main__":
    raise SystemExit(main())
