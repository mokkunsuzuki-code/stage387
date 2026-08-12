#!/usr/bin/env python3

import hashlib
import json
import os
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]

EXPECTED_ALGORITHM = "ML-DSA-65"
EXPECTED_FIPS_STANDARD = "FIPS 204"
EXPECTED_CONTEXT = "QSP-Stage375-v1"
EXPECTED_CIRCL_VERSION = "v1.6.5"

FORBIDDEN_TRACKED_COMPONENTS = {
    "core",
    "private_core",
    "private",
    "secrets",
    "keys",
    "imported",
}

PRIVATE_PEM_HEADERS = {
    "-----BEGIN PRIVATE KEY-----",
    "-----BEGIN RSA PRIVATE KEY-----",
    "-----BEGIN EC PRIVATE KEY-----",
    "-----BEGIN OPENSSH PRIVATE KEY-----",
}


POLICY_PATH = (
    ROOT
    / "development/stage387/"
    "stage387_pqc_interoperability_policy.json"
)

PUBLIC_KEY_PEM = (
    ROOT
    / "docs/mldsa-production/"
    "stage375_mldsa65_public_key.pem"
)

SIGNATURE = (
    ROOT
    / "docs/mldsa-production/"
    "stage375_mldsa65_signature.bin"
)

SIGNED_TARGET = (
    ROOT
    / "docs/final-acceptance-attestation/"
    "stage373_final_acceptance_attestation.json"
)

CIRCL_SOURCE = (
    ROOT
    / "development/stage387/"
    "stage387_circl_mldsa65_verifier.go"
)

GO_MODULE_DIR = (
    ROOT
    / "development/stage387"
)

RESULT_PATH = (
    ROOT
    / "development/stage387/"
    "stage387_pqc_multi_implementation_interoperability_result.json"
)

RESULT_SHA256_PATH = (
    ROOT
    / "development/stage387/"
    "stage387_pqc_multi_implementation_interoperability_result.sha256"
)



def sha256_file(path: Path) -> str:
    return hashlib.sha256(
        path.read_bytes()
    ).hexdigest()


def run_command(args, cwd=None):
    return subprocess.run(
        args,
        cwd=cwd,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )


def read_der_length(data: bytes, pos: int):
    first = data[pos]
    pos += 1

    if first < 0x80:
        return first, pos

    count = first & 0x7F

    if count == 0:
        raise ValueError(
            "Indefinite DER length is not allowed."
        )

    if count > 4:
        raise ValueError(
            "Unexpected DER length encoding."
        )

    if pos + count > len(data):
        raise ValueError(
            "Truncated DER length."
        )

    value = int.from_bytes(
        data[pos:pos + count],
        "big",
    )

    return value, pos + count


def extract_raw_mldsa_public_key(
    der: bytes,
) -> bytes:
    pos = 0

    if not der or der[pos] != 0x30:
        raise ValueError(
            "SPKI outer SEQUENCE missing."
        )

    outer_len, pos = read_der_length(
        der,
        pos + 1,
    )

    if pos + outer_len != len(der):
        raise ValueError(
            "SPKI outer length mismatch."
        )

    if der[pos] != 0x30:
        raise ValueError(
            "AlgorithmIdentifier missing."
        )

    alg_len, alg_content = read_der_length(
        der,
        pos + 1,
    )

    pos = alg_content + alg_len

    if pos >= len(der) or der[pos] != 0x03:
        raise ValueError(
            "Public-key BIT STRING missing."
        )

    bit_len, bit_content = read_der_length(
        der,
        pos + 1,
    )

    bit_end = bit_content + bit_len

    if bit_end != len(der):
        raise ValueError(
            "BIT STRING boundary mismatch."
        )

    if der[bit_content] != 0:
        raise ValueError(
            "BIT STRING unused bits are non-zero."
        )

    raw = der[
        bit_content + 1:
        bit_end
    ]

    if len(raw) != 1952:
        raise ValueError(
            "Unexpected ML-DSA-65 raw public-key size."
        )

    return raw


def write_verified_result(
    *,
    context,
    pem_sha,
    der_sha,
    raw_sha,
    signature_sha,
    target_sha,
    openssl_verified,
    circl_verified,
    result_match,
):
    result = {
        "stage": 387,
        "engine": (
            "PQC Multi-Implementation "
            "Interoperability & Verifier "
            "Independence Gate"
        ),
        "source_stage": 386,
        "decision": (
            "pqc_multi_implementation_"
            "interoperability_verified"
        ),
        "verification_status": "verified",
        "algorithm": "ML-DSA-65",
        "fips_standard": "FIPS 204",
        "context_string": context,
        "implementations": {
            "implementation_a": {
                "name": "OpenSSL",
                "verified": openssl_verified,
            },
            "implementation_b": {
                "name": "Cloudflare CIRCL",
                "version": "v1.6.5",
                "verified": circl_verified,
            },
        },
        "observations": {
            "public_key_pem_sha256": pem_sha,
            "public_key_der_sha256": der_sha,
            "raw_public_key_sha256": raw_sha,
            "signature_sha256": signature_sha,
            "signed_target_sha256": target_sha,
        },
        "checks": {
            "public_key_pem_sha256_matches": True,
            "public_key_der_sha256_matches": True,
            "raw_public_key_sha256_matches": True,
            "signature_sha256_matches": True,
            "signed_target_sha256_matches": True,
            "openssl_mldsa65_verified": (
                openssl_verified
            ),
            "circl_mldsa65_verified": (
                circl_verified
            ),
            "cross_implementation_result_match": (
                result_match
            ),
            "same_public_key": True,
            "same_signature": True,
            "same_signed_target": True,
            "same_context": True,
            "new_key_generated": False,
            "new_signature_generated": False,
            "private_key_published": False,
        },
        "limitations": {
            "entire_system_quantum_safe": False,
            "dual_timestamp_final_acceptance_complete": False,
            "system_wide_formal_acceptance_complete": False,
        },
    }

    payload = json.dumps(
        result,
        ensure_ascii=False,
        sort_keys=True,
        indent=2,
    ) + "\n"

    RESULT_PATH.write_text(
        payload,
        encoding="utf-8",
    )

    result_sha = hashlib.sha256(
        payload.encode("utf-8")
    ).hexdigest()

    RESULT_SHA256_PATH.write_text(
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

    return result_sha



def check_repository_security_boundary():
    git = shutil.which("git")

    if not git:
        return (
            False,
            "Git executable not found.",
        )

    proc = run_command(
        [
            git,
            "ls-files",
        ],
        cwd=ROOT,
    )

    if proc.returncode != 0:
        return (
            False,
            "Unable to enumerate tracked files.",
        )

    tracked = [
        line.strip()
        for line in proc.stdout.splitlines()
        if line.strip()
    ]

    forbidden = []

    for relative in tracked:
        parts = Path(relative).parts

        if any(
            part in FORBIDDEN_TRACKED_COMPONENTS
            for part in parts
        ):
            forbidden.append(relative)

    if forbidden:
        return (
            False,
            "Forbidden tracked paths: "
            + ", ".join(sorted(forbidden)),
        )

    for relative in tracked:
        path = ROOT / relative

        if not path.is_file():
            continue

        try:
            with path.open(
                "r",
                encoding="utf-8",
                errors="ignore",
            ) as handle:
                first_nonempty = ""

                for line in handle:
                    stripped = line.strip()

                    if stripped:
                        first_nonempty = stripped
                        break

        except OSError:
            continue

        if first_nonempty in PRIVATE_PEM_HEADERS:
            return (
                False,
                "Tracked private-key PEM detected: "
                + relative,
            )

    return (
        True,
        "",
    )


def get_circl_module_version():
    go = shutil.which("go")

    if not go:
        return (
            None,
            "Go executable not found.",
        )

    proc = run_command(
        [
            go,
            "list",
            "-m",
            "-f",
            "{{.Version}}",
            "github.com/cloudflare/circl",
        ],
        cwd=GO_MODULE_DIR,
    )

    if proc.returncode != 0:
        return (
            None,
            proc.stderr.strip()
            or proc.stdout.strip(),
        )

    return (
        proc.stdout.strip(),
        "",
    )



def fail(decision: str, message: str):
    print("stage = 387")
    print("decision =", decision)
    print("verification_status = failed")
    print("reason =", message)
    return 1


def main():
    if not POLICY_PATH.is_file():
        return fail(
            "fail_closed",
            "Stage387 policy missing.",
        )

    policy = json.loads(
        POLICY_PATH.read_text(
            encoding="utf-8"
        )
    )

    expected = policy["expected"]
    context = policy["context_string"]

    if policy.get("stage") != 387:
        return fail(
            "stage387_policy_stage_mismatch",
            "Stage387 policy stage identifier mismatch.",
        )

    if policy.get("source_stage") != 386:
        return fail(
            "stage387_source_stage_mismatch",
            "Stage387 source-stage binding mismatch.",
        )

    if (
        policy.get("algorithm")
        != EXPECTED_ALGORITHM
    ):
        return fail(
            "pqc_algorithm_identifier_mismatch",
            "Algorithm must remain ML-DSA-65.",
        )

    if (
        policy.get("fips_standard")
        != EXPECTED_FIPS_STANDARD
    ):
        return fail(
            "pqc_fips_standard_mismatch",
            "FIPS standard binding mismatch.",
        )

    if context != EXPECTED_CONTEXT:
        return fail(
            "pqc_context_string_mismatch",
            "ML-DSA context binding mismatch.",
        )

    implementation_b = (
        policy.get(
            "implementations",
            {},
        ).get(
            "implementation_b",
            {},
        )
    )

    if (
        implementation_b.get("name")
        != "Cloudflare CIRCL"
    ):
        return fail(
            "pqc_secondary_verifier_mismatch",
            "Secondary verifier identity mismatch.",
        )

    if (
        implementation_b.get("version")
        != EXPECTED_CIRCL_VERSION
    ):
        return fail(
            "pqc_circl_policy_version_mismatch",
            "CIRCL policy version must remain v1.6.5.",
        )

    boundary_ok, boundary_reason = (
        check_repository_security_boundary()
    )

    if not boundary_ok:
        return fail(
            "fail_closed",
            boundary_reason,
        )

    actual_circl_version, version_error = (
        get_circl_module_version()
    )

    if actual_circl_version is None:
        return fail(
            "circl_verifier_unavailable",
            version_error,
        )

    if (
        actual_circl_version
        != EXPECTED_CIRCL_VERSION
    ):
        return fail(
            "pqc_circl_runtime_version_mismatch",
            (
                "Expected CIRCL "
                + EXPECTED_CIRCL_VERSION
                + ", observed "
                + actual_circl_version
            ),
        )

    required_files = (
        PUBLIC_KEY_PEM,
        SIGNATURE,
        SIGNED_TARGET,
        CIRCL_SOURCE,
    )

    for path in required_files:
        if not path.is_file():
            return fail(
                "fail_closed",
                f"Required file missing: {path}",
            )

    actual_pem_sha = sha256_file(
        PUBLIC_KEY_PEM
    )

    if (
        actual_pem_sha
        != expected[
            "public_key_pem_sha256"
        ]
    ):
        return fail(
            "pqc_public_key_pem_hash_mismatch",
            "Public-key PEM SHA-256 mismatch.",
        )

    signature_sha = sha256_file(
        SIGNATURE
    )

    if (
        signature_sha
        != expected["signature_sha256"]
    ):
        return fail(
            "pqc_signature_hash_mismatch",
            "Signature SHA-256 mismatch.",
        )

    target_sha = sha256_file(
        SIGNED_TARGET
    )

    if (
        target_sha
        != expected[
            "signed_target_sha256"
        ]
    ):
        return fail(
            "pqc_signed_target_hash_mismatch",
            "Signed-target SHA-256 mismatch.",
        )

    openssl = shutil.which("openssl")

    if not openssl:
        return fail(
            "openssl_verifier_unavailable",
            "OpenSSL executable not found.",
        )

    go = shutil.which("go")

    if not go:
        return fail(
            "circl_verifier_unavailable",
            "Go executable not found.",
        )

    with tempfile.TemporaryDirectory(
        prefix="stage387-"
    ) as temp_name:
        temp_dir = Path(temp_name)

        der_path = (
            temp_dir
            / "stage375_public_key.der"
        )

        raw_path = (
            temp_dir
            / "stage375_public_key.raw"
        )

        circl_binary = (
            temp_dir
            / "stage387-circl-verifier"
        )

        der_proc = run_command(
            [
                openssl,
                "pkey",
                "-pubin",
                "-in",
                str(PUBLIC_KEY_PEM),
                "-outform",
                "DER",
                "-out",
                str(der_path),
            ]
        )

        if der_proc.returncode != 0:
            return fail(
                "pqc_public_key_der_conversion_failed",
                der_proc.stderr.strip(),
            )

        der_sha = sha256_file(
            der_path
        )

        if (
            der_sha
            != expected[
                "public_key_der_sha256"
            ]
        ):
            return fail(
                "pqc_public_key_der_hash_mismatch",
                "Public-key DER SHA-256 mismatch.",
            )

        try:
            raw_key = (
                extract_raw_mldsa_public_key(
                    der_path.read_bytes()
                )
            )
        except Exception as exc:
            return fail(
                "pqc_raw_public_key_extraction_failed",
                str(exc),
            )

        raw_path.write_bytes(
            raw_key
        )

        raw_sha = sha256_file(
            raw_path
        )

        if (
            raw_sha
            != expected[
                "raw_public_key_sha256"
            ]
        ):
            return fail(
                "pqc_raw_public_key_hash_mismatch",
                "Raw public-key SHA-256 mismatch.",
            )

        openssl_proc = run_command(
            [
                openssl,
                "pkeyutl",
                "-verify",
                "-in",
                str(SIGNED_TARGET),
                "-pubin",
                "-inkey",
                str(PUBLIC_KEY_PEM),
                "-sigfile",
                str(SIGNATURE),
                "-pkeyopt",
                f"context-string:{context}",
            ]
        )

        openssl_verified = (
            openssl_proc.returncode == 0
        )

        build_proc = run_command(
            [
                go,
                "build",
                "-o",
                str(circl_binary),
                "stage387_circl_mldsa65_verifier.go",
            ],
            cwd=GO_MODULE_DIR,
        )

        if build_proc.returncode != 0:
            return fail(
                "circl_verifier_build_failed",
                build_proc.stderr.strip(),
            )

        circl_proc = run_command(
            [
                str(circl_binary),
                "-public-key-raw",
                str(raw_path),
                "-signature",
                str(SIGNATURE),
                "-message",
                str(SIGNED_TARGET),
                "-context",
                context,
            ]
        )

        circl_verified = (
            circl_proc.returncode == 0
            and
            "circl_mldsa65_verified = true"
            in circl_proc.stdout
        )

        result_match = (
            openssl_verified
            == circl_verified
        )

        if not openssl_verified:
            return fail(
                "openssl_mldsa65_verification_failed",
                (
                    openssl_proc.stderr.strip()
                    or
                    openssl_proc.stdout.strip()
                ),
            )

        if not circl_verified:
            return fail(
                "circl_mldsa65_verification_failed",
                (
                    circl_proc.stderr.strip()
                    or
                    circl_proc.stdout.strip()
                ),
            )

        if not result_match:
            return fail(
                "pqc_cross_implementation_result_mismatch",
                "Verifier results disagree.",
            )

        result_sha = write_verified_result(
            context=context,
            pem_sha=actual_pem_sha,
            der_sha=der_sha,
            raw_sha=raw_sha,
            signature_sha=signature_sha,
            target_sha=target_sha,
            openssl_verified=openssl_verified,
            circl_verified=circl_verified,
            result_match=result_match,
        )


        print("stage = 387")
        print(
            "decision =",
            "pqc_multi_implementation_interoperability_verified",
        )
        print(
            "verification_status = verified"
        )
        print(
            "algorithm = ML-DSA-65"
        )
        print(
            "context =",
            context,
        )
        print(
            "public_key_pem_sha256_matches = True"
        )
        print(
            "public_key_der_sha256_matches = True"
        )
        print(
            "raw_public_key_sha256_matches = True"
        )
        print(
            "signature_sha256_matches = True"
        )
        print(
            "signed_target_sha256_matches = True"
        )
        print(
            "openssl_mldsa65_verified =",
            openssl_verified,
        )
        print(
            "circl_mldsa65_verified =",
            circl_verified,
        )
        print(
            "cross_implementation_result_match =",
            result_match,
        )
        print(
            "new_key_generated = False"
        )
        print(
            "new_signature_generated = False"
        )
        print(
            "private_key_published = False"
        )
        print(
            "entire_system_quantum_safe = False"
        )
        print(
            "result_sha256 =",
            result_sha,
        )

        return 0


if __name__ == "__main__":
    raise SystemExit(main())
