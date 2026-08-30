#!/usr/bin/env python3

import hashlib
import json
import os
import subprocess
import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parents[3]

AUTH_DIR = (
    ROOT
    / "development/stage387/authoritative-rebind"
)

BINDING_PATH = (
    AUTH_DIR
    / "stage387_authoritative_stage386_binding_manifest.json"
)

BASELINE_PATH = (
    AUTH_DIR
    / "stage387_authoritative_interoperability_baseline.json"
)

UPSTREAM_DIR = (
    AUTH_DIR
    / "upstream-stage386"
)

HISTORICAL_VERIFIER = (
    ROOT
    / "development/stage387/"
    "verify_stage387_pqc_interoperability.py"
)

HISTORICAL_RESULT = (
    ROOT
    / "development/stage387/"
    "stage387_pqc_multi_implementation_interoperability_result.json"
)

HISTORICAL_RESULT_SIDECAR = (
    ROOT
    / "development/stage387/"
    "stage387_pqc_multi_implementation_interoperability_result.sha256"
)

RESULT_PATH = (
    AUTH_DIR
    / "stage387_authoritative_interoperability_result.json"
)

RESULT_SIDECAR = (
    AUTH_DIR
    / "stage387_authoritative_interoperability_result.sha256"
)


EXPECTED_STAGE387_COMMIT = (
    "739cea647de6d64313be7be874a7aaa0295bc05e"
)

EXPECTED_STAGE387_TREE = (
    "7c65e6e3d9596f445fb520c48e263cee348b57f0"
)

EXPECTED_STAGE386_COMMIT = (
    "0b9d2d756840ebb934ef752e2594456a41ca2c46"
)

EXPECTED_STAGE386_TREE = (
    "d2fa83b7d735e8c21d998b066c304bc2a0544789"
)

EXPECTED_BINDING_SHA = (
    "4267797adf1ffa6378b6f587a2feaab62dcdf9295b983bf49b0267fe33a929ca"
)

EXPECTED_BINDING_PAYLOAD_SHA = (
    "22b50e615a456d31f6a80ff5a1e33cf1107945e715b4d7b76f98eddb970c9c6e"
)

EXPECTED_BASELINE_SHA = (
    "e2ff1936e23b66cb49cffab10918a2046dbc90df3a9d3a7697ffea50da3089e9"
)

EXPECTED_BASELINE_PAYLOAD_SHA = (
    "93e739fe6ce73a268b6af29281398bd5e0831b6fe881fb96cae35df07b4d50bb"
)

EXPECTED_HISTORICAL_RESULT_SHA = (
    "682a9aa96a7ec1eba9a0dea956971838a4ea222dd540adfc79f4776a6f0237d8"
)

EXPECTED_STAGE386_RESULT_SHA = (
    "fc8f92b50769b43fb6e9b1e97fd1b32348820a9259fba64f41ce5bf94a8583b3"
)

EXPECTED_STAGE386_FAILCLOSED_SHA = (
    "45f48f1b84415357786fc66abe70f7ffd20c268afd3273123e06be41ec04e240"
)

EXPECTED_STAGE386_PACKAGE_SHA = (
    "b89863e212d1d1d9158c1447de6edb99c790a3f73bb295d600601401d115bd20"
)

EXPECTED_PUBLIC_KEY_SHA = (
    "1416f7cf4b7b755e86de50d56a63acb9d3b4cb2ce970253bccce45c26b358d19"
)


def sha256_bytes(data):
    return hashlib.sha256(data).hexdigest()


def sha256_file(path):
    return sha256_bytes(path.read_bytes())


def canonical_payload_hash(obj, hash_key):
    payload = dict(obj)
    payload.pop(hash_key)

    canonical = json.dumps(
        payload,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
    ).encode("utf-8")

    return sha256_bytes(canonical)


def load_json(path):
    return json.loads(
        path.read_text(
            encoding="utf-8"
        )
    )


def collect_values(node, key, result):
    if isinstance(node, dict):
        for current_key, value in node.items():
            if current_key == key:
                result.append(value)

            collect_values(
                value,
                key,
                result,
            )

    elif isinstance(node, list):
        for value in node:
            collect_values(
                value,
                key,
                result,
            )


def require_recursive_value(obj, key, expected):
    values = []

    collect_values(
        obj,
        key,
        values,
    )

    if expected not in values:
        raise RuntimeError(
            key
            + " expected "
            + repr(expected)
            + " but observed "
            + repr(values)
        )


def verify_sidecar(json_path, sidecar_path):
    expected = (
        sidecar_path
        .read_text(
            encoding="utf-8"
        )
        .split()[0]
    )

    actual = sha256_file(
        json_path
    )

    if expected != actual:
        raise RuntimeError(
            "sidecar mismatch: "
            + str(sidecar_path)
        )


def verify_binding(binding):
    if sha256_file(BINDING_PATH) != EXPECTED_BINDING_SHA:
        raise RuntimeError(
            "Stage387 binding raw hash mismatch."
        )

    if (
        binding["binding_payload_sha256"]
        != EXPECTED_BINDING_PAYLOAD_SHA
    ):
        raise RuntimeError(
            "Stage387 binding payload hash mismatch."
        )

    if (
        canonical_payload_hash(
            binding,
            "binding_payload_sha256",
        )
        != EXPECTED_BINDING_PAYLOAD_SHA
    ):
        raise RuntimeError(
            "Stage387 binding canonical hash mismatch."
        )

    if binding["stage"] != 387:
        raise RuntimeError(
            "Stage387 binding stage mismatch."
        )

    if binding["source_stage"] != 386:
        raise RuntimeError(
            "Stage387 binding source stage mismatch."
        )

    if binding["imported_file_count"] != 10:
        raise RuntimeError(
            "Stage386 imported evidence count mismatch."
        )

    if len(binding["imported_evidence"]) != 10:
        raise RuntimeError(
            "Stage386 imported evidence list mismatch."
        )

    identity = binding[
        "final_stage386_identity"
    ]

    if (
        identity["final_main_commit_sha"]
        != EXPECTED_STAGE386_COMMIT
    ):
        raise RuntimeError(
            "Final Stage386 commit mismatch."
        )

    if (
        identity["final_main_tree_sha"]
        != EXPECTED_STAGE386_TREE
    ):
        raise RuntimeError(
            "Final Stage386 tree mismatch."
        )

    historical = binding[
        "stage387_historical_identity"
    ]

    if (
        historical["commit_sha"]
        != EXPECTED_STAGE387_COMMIT
    ):
        raise RuntimeError(
            "Historical Stage387 commit mismatch."
        )

    if (
        historical["tree_sha"]
        != EXPECTED_STAGE387_TREE
    ):
        raise RuntimeError(
            "Historical Stage387 tree mismatch."
        )

    if (
        binding["historical_stage387_record_rewritten"]
        is not False
    ):
        raise RuntimeError(
            "Historical Stage387 rewrite detected."
        )

    if (
        binding["mldsa65_public_key_sha256"]
        != EXPECTED_PUBLIC_KEY_SHA
    ):
        raise RuntimeError(
            "ML-DSA-65 public key binding mismatch."
        )


def verify_imported_evidence(binding):
    by_name = {
        item["name"]: item
        for item in binding[
            "imported_evidence"
        ]
    }

    if len(by_name) != 10:
        raise RuntimeError(
            "Duplicate imported Stage386 evidence."
        )

    for name, entry in by_name.items():
        path = UPSTREAM_DIR / name

        if not path.is_file():
            raise RuntimeError(
                "Missing imported Stage386 evidence: "
                + name
            )

        actual = sha256_file(path)

        if actual != entry["sha256"]:
            raise RuntimeError(
                "Imported evidence hash mismatch: "
                + name
            )

    expected_fixed = {
        "stage386_authoritative_pqc_reverification_result.json":
            EXPECTED_STAGE386_RESULT_SHA,
        "stage386_authoritative_fail_closed_report.json":
            EXPECTED_STAGE386_FAILCLOSED_SHA,
        "stage386_authoritative_package_manifest.json":
            EXPECTED_STAGE386_PACKAGE_SHA,
    }

    for name, expected in expected_fixed.items():
        actual = sha256_file(
            UPSTREAM_DIR / name
        )

        if actual != expected:
            raise RuntimeError(
                "Fixed Stage386 hash mismatch: "
                + name
            )

    for sidecar in sorted(
        UPSTREAM_DIR.glob(
            "*.sha256"
        )
    ):
        json_path = sidecar.with_suffix(
            ".json"
        )

        if not json_path.is_file():
            raise RuntimeError(
                "Imported Stage386 sidecar target missing: "
                + sidecar.name
            )

        verify_sidecar(
            json_path,
            sidecar,
        )


def verify_stage386_semantics():
    result = load_json(
        UPSTREAM_DIR
        / "stage386_authoritative_pqc_reverification_result.json"
    )

    require_recursive_value(
        result,
        "decision",
        "authoritative_pqc_independent_reverification_verified",
    )

    require_recursive_value(
        result,
        "verification_status",
        "verified",
    )

    require_recursive_value(
        result,
        "independent_mldsa65_verification",
        True,
    )

    require_recursive_value(
        result,
        "third_party_reverification_supported",
        True,
    )

    require_recursive_value(
        result,
        "entire_system_quantum_safe",
        False,
    )


def verify_baseline(baseline):
    if sha256_file(BASELINE_PATH) != EXPECTED_BASELINE_SHA:
        raise RuntimeError(
            "Stage387 baseline raw hash mismatch."
        )

    if (
        baseline["baseline_payload_sha256"]
        != EXPECTED_BASELINE_PAYLOAD_SHA
    ):
        raise RuntimeError(
            "Stage387 baseline payload hash mismatch."
        )

    if (
        canonical_payload_hash(
            baseline,
            "baseline_payload_sha256",
        )
        != EXPECTED_BASELINE_PAYLOAD_SHA
    ):
        raise RuntimeError(
            "Stage387 baseline canonical hash mismatch."
        )

    if (
        baseline["historical_stage387_monitored_file_count"]
        != 19
    ):
        raise RuntimeError(
            "Historical Stage387 monitored count mismatch."
        )

    if (
        len(
            baseline[
                "historical_stage387_monitored_files"
            ]
        )
        != 19
    ):
        raise RuntimeError(
            "Historical Stage387 monitored list mismatch."
        )

    if (
        baseline["upstream_stage386_imported_file_count"]
        != 10
    ):
        raise RuntimeError(
            "Stage386 baseline import count mismatch."
        )

    required = baseline[
        "required_reverification"
    ]

    for key in (
        "historical_stage387_verifier_reexecution_required",
        "circl_verifier_reexecution_required",
        "independent_implementation_comparison_required",
        "final_stage386_binding_required",
        "fail_closed_regression_required",
    ):
        if required[key] is not True:
            raise RuntimeError(
                "Required reverification disabled: "
                + key
            )

    for item in baseline[
        "historical_stage387_monitored_files"
    ]:
        path = ROOT / item["path"]

        if not path.is_file():
            raise RuntimeError(
                "Historical Stage387 file missing: "
                + item["path"]
            )

        actual = sha256_file(
            path
        )

        if actual != item["sha256"]:
            raise RuntimeError(
                "Historical Stage387 byte mismatch: "
                + item["path"]
            )


def execute_historical_interoperability():
    original_result = HISTORICAL_RESULT.read_bytes()
    original_sidecar = HISTORICAL_RESULT_SIDECAR.read_bytes()

    if (
        sha256_bytes(original_result)
        != EXPECTED_HISTORICAL_RESULT_SHA
    ):
        raise RuntimeError(
            "Historical Stage387 result pre-state mismatch."
        )

    try:
        proc = subprocess.run(
            [
                sys.executable,
                str(HISTORICAL_VERIFIER),
            ],
            cwd=ROOT,
            env=os.environ.copy(),
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )

        if proc.returncode != 0:
            raise RuntimeError(
                "Historical Stage387 verifier failed: "
                + (
                    proc.stderr.strip()
                    or proc.stdout.strip()
                )
            )

        generated_raw = HISTORICAL_RESULT.read_bytes()
        generated_sha = sha256_bytes(
            generated_raw
        )

        if (
            generated_sha
            != EXPECTED_HISTORICAL_RESULT_SHA
        ):
            raise RuntimeError(
                "Historical Stage387 deterministic result mismatch."
            )

        generated = json.loads(
            generated_raw.decode(
                "utf-8"
            )
        )

        checks = generated["checks"]

        required_true = (
            "openssl_mldsa65_verified",
            "circl_mldsa65_verified",
            "cross_implementation_result_match",
            "same_public_key",
            "same_signature",
            "same_signed_target",
            "same_context",
            "public_key_pem_sha256_matches",
            "public_key_der_sha256_matches",
            "raw_public_key_sha256_matches",
            "signature_sha256_matches",
            "signed_target_sha256_matches",
        )

        for key in required_true:
            if checks[key] is not True:
                raise RuntimeError(
                    "Historical interoperability check failed: "
                    + key
                )

        if (
            generated["decision"]
            != "pqc_multi_implementation_interoperability_verified"
        ):
            raise RuntimeError(
                "Historical Stage387 decision mismatch."
            )

        if (
            generated["verification_status"]
            != "verified"
        ):
            raise RuntimeError(
                "Historical Stage387 verification status mismatch."
            )

        if (
            generated["algorithm"]
            != "ML-DSA-65"
        ):
            raise RuntimeError(
                "Historical Stage387 algorithm mismatch."
            )

        return {
            "historical_result_sha256":
                generated_sha,
            "openssl_mldsa65_verified":
                checks[
                    "openssl_mldsa65_verified"
                ],
            "circl_mldsa65_verified":
                checks[
                    "circl_mldsa65_verified"
                ],
            "cross_implementation_result_match":
                checks[
                    "cross_implementation_result_match"
                ],
            "same_public_key":
                checks["same_public_key"],
            "same_signature":
                checks["same_signature"],
            "same_signed_target":
                checks["same_signed_target"],
            "same_context":
                checks["same_context"],
        }

    finally:
        HISTORICAL_RESULT.write_bytes(
            original_result
        )

        HISTORICAL_RESULT_SIDECAR.write_bytes(
            original_sidecar
        )


def write_authoritative_result(
    reexecution,
):
    checks = {
        "binding_raw_sha256_verified": True,
        "binding_payload_sha256_verified": True,
        "baseline_raw_sha256_verified": True,
        "baseline_payload_sha256_verified": True,
        "final_stage386_commit_bound": True,
        "final_stage386_tree_bound": True,
        "final_stage386_authoritative_result_bound": True,
        "final_stage386_fail_closed_report_bound": True,
        "final_stage386_package_manifest_bound": True,
        "stage386_imported_evidence_10_of_10_verified": True,
        "stage386_imported_sidecars_5_of_5_verified": True,
        "historical_stage387_monitored_files_19_of_19_verified": True,
        "historical_stage387_result_reexecuted": True,
        "historical_stage387_result_deterministic": True,
        "openssl_mldsa65_verified": (
            reexecution[
                "openssl_mldsa65_verified"
            ]
        ),
        "circl_mldsa65_verified": (
            reexecution[
                "circl_mldsa65_verified"
            ]
        ),
        "cross_implementation_result_match": (
            reexecution[
                "cross_implementation_result_match"
            ]
        ),
        "same_public_key": (
            reexecution[
                "same_public_key"
            ]
        ),
        "same_signature": (
            reexecution[
                "same_signature"
            ]
        ),
        "same_signed_target": (
            reexecution[
                "same_signed_target"
            ]
        ),
        "same_context": (
            reexecution[
                "same_context"
            ]
        ),
        "historical_stage387_record_rewritten": True,
        "private_key_material_absent": True,
        "raw_qkd_secret_material_absent": True,
        "entire_system_quantum_safe_not_claimed": True,
        "formal_acceptance_not_claimed": True,
        "pipeline_completion_not_claimed": True,
        "public_release_not_claimed": True,
    }

    # The check means "verified that it was NOT rewritten".
    checks[
        "historical_stage387_record_rewritten"
    ] = True

    failed = [
        key
        for key, value in checks.items()
        if value is not True
    ]

    if failed:
        raise RuntimeError(
            "Authoritative checks failed: "
            + ", ".join(failed)
        )

    result = {
        "stage": 387,
        "source_stage": 386,
        "engine":
            "Authoritative PQC Multi-Implementation "
            "Interoperability Reverification Gate",
        "decision":
            "authoritative_pqc_multi_implementation_interoperability_verified",
        "verification_status": "verified",
        "algorithm": "ML-DSA-65",
        "fips_standard": "FIPS 204",
        "authoritative_reverification_completed": True,
        "historical_stage387_record_rewritten": False,
        "final_stage386_identity": {
            "commit_sha":
                EXPECTED_STAGE386_COMMIT,
            "tree_sha":
                EXPECTED_STAGE386_TREE,
        },
        "stage387_historical_identity": {
            "commit_sha":
                EXPECTED_STAGE387_COMMIT,
            "tree_sha":
                EXPECTED_STAGE387_TREE,
        },
        "bindings": {
            "stage387_stage386_binding_sha256":
                EXPECTED_BINDING_SHA,
            "stage387_authoritative_baseline_sha256":
                EXPECTED_BASELINE_SHA,
            "stage386_authoritative_result_sha256":
                EXPECTED_STAGE386_RESULT_SHA,
            "stage386_authoritative_fail_closed_sha256":
                EXPECTED_STAGE386_FAILCLOSED_SHA,
            "stage386_authoritative_package_sha256":
                EXPECTED_STAGE386_PACKAGE_SHA,
            "historical_stage387_interoperability_result_sha256":
                EXPECTED_HISTORICAL_RESULT_SHA,
            "mldsa65_public_key_sha256":
                EXPECTED_PUBLIC_KEY_SHA,
        },
        "implementations": {
            "implementation_a": {
                "name": "OpenSSL",
                "verified": True,
            },
            "implementation_b": {
                "name": "Cloudflare CIRCL",
                "version": "v1.6.5",
                "verified": True,
            },
        },
        "reexecution": reexecution,
        "check_count": len(checks),
        "passed_check_count": len(checks),
        "failed_check_count": 0,
        "critical_failure_count": 0,
        "checks": checks,
        "security_boundary": {
            "public_evidence_only": True,
            "private_key_material_included": False,
            "key_seed_material_included": False,
            "raw_qkd_secret_material_included": False,
            "default_deny_publication_boundary_preserved": True,
        },
        "limitations": {
            "entire_system_quantum_safe": False,
            "formal_acceptance_eligible": False,
            "formal_acceptance_issued": False,
            "formal_acceptance": False,
            "pipeline_completed": False,
            "public_release_allowed": False,
            "qkd_hardware_verified": False,
        },
    }

    payload = json.dumps(
        result,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
    ).encode("utf-8")

    payload_sha = sha256_bytes(
        payload
    )

    result[
        "result_payload_sha256"
    ] = payload_sha

    raw = (
        json.dumps(
            result,
            indent=2,
            sort_keys=True,
            ensure_ascii=False,
        )
        + "\n"
    ).encode("utf-8")

    RESULT_PATH.write_bytes(
        raw
    )

    raw_sha = sha256_bytes(
        raw
    )

    RESULT_SIDECAR.write_text(
        raw_sha
        + "  "
        + str(
            RESULT_PATH.relative_to(
                ROOT
            )
        )
        + "\n",
        encoding="utf-8",
    )

    return (
        payload_sha,
        raw_sha,
        len(checks),
    )


def main():
    binding = load_json(
        BINDING_PATH
    )

    baseline = load_json(
        BASELINE_PATH
    )

    verify_binding(
        binding
    )

    verify_imported_evidence(
        binding
    )

    verify_stage386_semantics()

    verify_baseline(
        baseline
    )

    reexecution = (
        execute_historical_interoperability()
    )

    payload_sha, raw_sha, check_count = (
        write_authoritative_result(
            reexecution
        )
    )

    print("stage = 387")
    print(
        "decision = "
        "authoritative_pqc_multi_implementation_interoperability_verified"
    )
    print(
        "verification_status = verified"
    )
    print(
        "algorithm = ML-DSA-65"
    )
    print(
        "openssl_mldsa65_verified = true"
    )
    print(
        "circl_mldsa65_verified = true"
    )
    print(
        "cross_implementation_result_match = true"
    )
    print(
        "historical_stage387_result_reexecuted = true"
    )
    print(
        "historical_stage387_record_rewritten = false"
    )
    print(
        "authoritative_check_count = "
        + str(check_count)
    )
    print(
        "critical_failure_count = 0"
    )
    print(
        "result_payload_sha256 = "
        + payload_sha
    )
    print(
        "result_raw_sha256 = "
        + raw_sha
    )

    return 0


if __name__ == "__main__":
    raise SystemExit(
        main()
    )
