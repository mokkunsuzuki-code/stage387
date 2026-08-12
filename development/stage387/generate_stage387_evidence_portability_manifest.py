#!/usr/bin/env python3

import hashlib
import json
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]

OUTPUT = (
    ROOT
    / "development/stage387/"
    "stage387_evidence_portability_manifest.json"
)

SHA_OUTPUT = (
    ROOT
    / "development/stage387/"
    "stage387_evidence_portability_manifest.sha256"
)


ARTIFACTS = [
    {
        "role": "stage387_policy",
        "path": (
            "development/stage387/"
            "stage387_pqc_interoperability_policy.json"
        ),
    },
    {
        "role": "stage387_policy_sha256_record",
        "path": (
            "development/stage387/"
            "stage387_pqc_interoperability_policy.sha256"
        ),
    },
    {
        "role": "stage387_python_gate",
        "path": (
            "development/stage387/"
            "verify_stage387_pqc_interoperability.py"
        ),
    },
    {
        "role": "stage387_circl_verifier",
        "path": (
            "development/stage387/"
            "stage387_circl_mldsa65_verifier.go"
        ),
    },
    {
        "role": "stage387_go_module",
        "path": (
            "development/stage387/go.mod"
        ),
    },
    {
        "role": "stage387_go_dependency_lock",
        "path": (
            "development/stage387/go.sum"
        ),
    },
    {
        "role": "stage387_fail_closed_tests",
        "path": (
            "development/stage387/"
            "test_stage387_fail_closed.py"
        ),
    },
    {
        "role": "stage387_verified_result",
        "path": (
            "development/stage387/"
            "stage387_pqc_multi_implementation_"
            "interoperability_result.json"
        ),
    },
    {
        "role": "stage387_result_sha256_record",
        "path": (
            "development/stage387/"
            "stage387_pqc_multi_implementation_"
            "interoperability_result.sha256"
        ),
    },
    {
        "role": "stage375_public_key",
        "path": (
            "docs/mldsa-production/"
            "stage375_mldsa65_public_key.pem"
        ),
    },
    {
        "role": "stage375_signature",
        "path": (
            "docs/mldsa-production/"
            "stage375_mldsa65_signature.bin"
        ),
    },
    {
        "role": "stage375_signed_target",
        "path": (
            "docs/final-acceptance-attestation/"
            "stage373_final_acceptance_attestation.json"
        ),
    },
    {
        "role": "stage375_execution_receipt",
        "path": (
            "docs/mldsa-production/"
            "stage375_mldsa65_execution_receipt.json"
        ),
    },
    {
        "role": "stage387_manifest_generator",
        "path": (
            "development/stage387/"
            "generate_stage387_evidence_portability_manifest.py"
        ),
    },
    {
        "role": "stage387_github_actions_workflow",
        "path": (
            ".github/workflows/"
            "stage387-pqc-multi-implementation-interoperability.yml"
        ),
    },
]


def sha256_file(path: Path) -> str:
    return hashlib.sha256(
        path.read_bytes()
    ).hexdigest()


def main():
    resolved = []

    for artifact in ARTIFACTS:
        relative = artifact["path"]
        path = ROOT / relative

        if not path.is_file():
            raise SystemExit(
                "FAIL: required portability "
                f"artifact missing: {relative}"
            )

        resolved.append(
            {
                "path": relative,
                "role": artifact["role"],
                "sha256": sha256_file(path),
                "size_bytes": path.stat().st_size,
            }
        )

    manifest = {
        "algorithm": "ML-DSA-65",
        "artifacts": resolved,
        "context_string": "QSP-Stage375-v1",
        "expected_result": {
            "circl_mldsa65_verified": True,
            "cross_implementation_result_match": True,
            "decision": (
                "pqc_multi_implementation_"
                "interoperability_verified"
            ),
            "openssl_mldsa65_verified": True,
            "verification_status": "verified",
        },
        "fips_standard": "FIPS 204",
        "implementations": [
            {
                "name": "OpenSSL",
                "role": "implementation_a",
            },
            {
                "name": "Cloudflare CIRCL",
                "role": "implementation_b",
                "version": "v1.6.5",
            },
        ],
        "limitations": {
            "dual_timestamp_final_acceptance_complete": False,
            "entire_system_quantum_safe": False,
            "system_wide_formal_acceptance_complete": False,
        },
        "name": (
            "PQC Multi-Implementation Interoperability "
            "& Verifier Independence Gate"
        ),
        "purpose": (
            "Deterministically identify the public evidence "
            "required to reproduce Stage387 multi-implementation "
            "ML-DSA-65 verification."
        ),
        "source_stage": 386,
        "stage": 387,
        "verification_model": {
            "dependency_acquisition_may_require_network": True,
            "network_required_for_cryptographic_verification": False,
            "new_key_generation_required": False,
            "new_signature_generation_required": False,
            "private_key_required": False,
            "public_evidence_only": True,
        },
    }

    payload = json.dumps(
        manifest,
        ensure_ascii=False,
        sort_keys=True,
        indent=2,
    ) + "\n"

    OUTPUT.write_text(
        payload,
        encoding="utf-8",
    )

    manifest_sha = hashlib.sha256(
        payload.encode("utf-8")
    ).hexdigest()

    SHA_OUTPUT.write_text(
        (
            manifest_sha
            + "  development/stage387/"
            "stage387_evidence_portability_manifest.json\n"
        ),
        encoding="utf-8",
    )

    print("stage = 387")
    print("artifact_count =", len(resolved))
    print("manifest_sha256 =", manifest_sha)
    print(
        "PASS: deterministic Stage387 "
        "evidence portability manifest generated"
    )

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
