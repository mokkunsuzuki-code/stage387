#!/usr/bin/env python3

import hashlib
import json
import os
import stat
import subprocess
import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parents[3]

AUTH = (
    ROOT
    / "development/stage387/authoritative-rebind"
)

VERIFIER = (
    AUTH
    / "verify_stage387_authoritative_interoperability.py"
)

RESULT = (
    AUTH
    / "stage387_authoritative_interoperability_result.json"
)

RESULT_SIDECAR = (
    AUTH
    / "stage387_authoritative_interoperability_result.sha256"
)

REPORT = (
    AUTH
    / "stage387_authoritative_fail_closed_report.json"
)

REPORT_SIDECAR = (
    AUTH
    / "stage387_authoritative_fail_closed_report.sha256"
)

EXPECTED_RESULT_SHA = (
    "e6bc2f2619159da19a499d5df53d7fa674feb99c21a19edc55ffc8f513667efb"
)

EXPECTED_HISTORICAL_RESULT_SHA = (
    "682a9aa96a7ec1eba9a0dea956971838a4ea222dd540adfc79f4776a6f0237d8"
)

BINDING = (
    AUTH
    / "stage387_authoritative_stage386_binding_manifest.json"
)

BASELINE = (
    AUTH
    / "stage387_authoritative_interoperability_baseline.json"
)

UPSTREAM = (
    AUTH
    / "upstream-stage386"
)

HISTORICAL_RESULT = (
    ROOT
    / "development/stage387/"
    "stage387_pqc_multi_implementation_interoperability_result.json"
)

HISTORICAL_POLICY = (
    ROOT
    / "development/stage387/"
    "stage387_pqc_interoperability_policy.json"
)

HISTORICAL_VERIFIER = (
    ROOT
    / "development/stage387/"
    "verify_stage387_pqc_interoperability.py"
)

PUBLIC_KEY = (
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


def sha256_bytes(data):
    return hashlib.sha256(
        data
    ).hexdigest()


def sha256_file(path):
    return sha256_bytes(
        path.read_bytes()
    )


def run_verifier():
    return subprocess.run(
        [
            sys.executable,
            str(VERIFIER),
        ],
        cwd=ROOT,
        env=os.environ.copy(),
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )


def mode_bits(path):
    return stat.S_IMODE(
        path.stat().st_mode
    )


def restore_file(path, data, mode):
    path.write_bytes(
        data
    )

    os.chmod(
        path,
        mode,
    )


def execute_scenario(
    name,
    path,
    mode,
    canonical_result,
    canonical_sidecar,
):
    existed = path.exists()

    original = (
        path.read_bytes()
        if existed
        else None
    )

    original_mode = (
        mode_bits(path)
        if existed
        else None
    )

    try:
        if mode == "append":
            if not existed:
                raise RuntimeError(
                    name
                    + ": target missing before test"
                )

            path.write_bytes(
                original + b"\n"
            )

            os.chmod(
                path,
                original_mode,
            )

        elif mode == "flip":
            if not existed:
                raise RuntimeError(
                    name
                    + ": target missing before test"
                )

            mutated = bytearray(
                original
            )

            if not mutated:
                raise RuntimeError(
                    name
                    + ": empty target"
                )

            mutated[0] ^= 0x01

            path.write_bytes(
                bytes(mutated)
            )

            os.chmod(
                path,
                original_mode,
            )

        elif mode == "missing":
            if not existed:
                raise RuntimeError(
                    name
                    + ": target missing before test"
                )

            path.unlink()

        else:
            raise RuntimeError(
                "Unknown mutation mode: "
                + mode
            )

        proc = run_verifier()

        if proc.returncode == 0:
            raise RuntimeError(
                name
                + ": verifier unexpectedly accepted mutation"
            )

        if (
            RESULT.read_bytes()
            != canonical_result
        ):
            raise RuntimeError(
                name
                + ": canonical positive result changed"
            )

        if (
            RESULT_SIDECAR.read_bytes()
            != canonical_sidecar
        ):
            raise RuntimeError(
                name
                + ": canonical result sidecar changed"
            )

        print(
            "FAIL_CLOSED_SCENARIO_PASS="
            + name
        )

        return {
            "name": name,
            "mutation": mode,
            "expected_fail_closed": True,
            "observed_fail_closed": True,
            "nonzero_exit_verified": True,
            "canonical_positive_result_unchanged": True,
            "original_file_mode": (
                format(
                    original_mode,
                    "o",
                )
                if original_mode is not None
                else None
            ),
            "mode_restoration_required": (
                mode == "missing"
            ),
        }

    finally:
        if existed:
            restore_file(
                path,
                original,
                original_mode,
            )

        elif path.exists():
            path.unlink()

        RESULT.write_bytes(
            canonical_result
        )

        RESULT_SIDECAR.write_bytes(
            canonical_sidecar
        )


def main():
    if sha256_file(RESULT) != EXPECTED_RESULT_SHA:
        raise RuntimeError(
            "Canonical authoritative result mismatch before tests."
        )

    if (
        sha256_file(HISTORICAL_RESULT)
        != EXPECTED_HISTORICAL_RESULT_SHA
    ):
        raise RuntimeError(
            "Historical Stage387 result mismatch before tests."
        )

    historical_verifier_mode_before = (
        mode_bits(
            HISTORICAL_VERIFIER
        )
    )

    canonical_result = (
        RESULT.read_bytes()
    )

    canonical_sidecar = (
        RESULT_SIDECAR.read_bytes()
    )

    scenarios = [
        (
            "binding_manifest_tamper",
            BINDING,
            "append",
        ),
        (
            "baseline_tamper",
            BASELINE,
            "append",
        ),
        (
            "imported_stage386_result_tamper",
            UPSTREAM
            / "stage386_authoritative_pqc_reverification_result.json",
            "append",
        ),
        (
            "imported_stage386_fail_closed_report_tamper",
            UPSTREAM
            / "stage386_authoritative_fail_closed_report.json",
            "append",
        ),
        (
            "imported_stage386_package_manifest_tamper",
            UPSTREAM
            / "stage386_authoritative_package_manifest.json",
            "append",
        ),
        (
            "imported_stage386_binding_manifest_tamper",
            UPSTREAM
            / "stage386_authoritative_rebind_binding_manifest.json",
            "append",
        ),
        (
            "imported_stage386_baseline_tamper",
            UPSTREAM
            / "stage386_authoritative_pqc_reverification_baseline.json",
            "append",
        ),
        (
            "imported_stage386_result_sidecar_tamper",
            UPSTREAM
            / "stage386_authoritative_pqc_reverification_result.sha256",
            "append",
        ),
        (
            "imported_stage386_package_manifest_missing",
            UPSTREAM
            / "stage386_authoritative_package_manifest.json",
            "missing",
        ),
        (
            "imported_stage386_binding_sidecar_missing",
            UPSTREAM
            / "stage386_authoritative_rebind_binding_manifest.sha256",
            "missing",
        ),
        (
            "historical_stage387_result_tamper",
            HISTORICAL_RESULT,
            "append",
        ),
        (
            "historical_stage387_policy_tamper",
            HISTORICAL_POLICY,
            "append",
        ),
        (
            "historical_stage387_verifier_missing",
            HISTORICAL_VERIFIER,
            "missing",
        ),
        (
            "mldsa65_public_key_tamper",
            PUBLIC_KEY,
            "append",
        ),
        (
            "mldsa65_signature_tamper",
            SIGNATURE,
            "flip",
        ),
        (
            "signed_target_tamper",
            SIGNED_TARGET,
            "append",
        ),
    ]

    results = []

    for name, path, mutation in scenarios:
        results.append(
            execute_scenario(
                name,
                path,
                mutation,
                canonical_result,
                canonical_sidecar,
            )
        )

    if len(results) != 16:
        raise RuntimeError(
            "Unexpected fail-closed scenario count."
        )

    if not all(
        item["observed_fail_closed"]
        for item in results
    ):
        raise RuntimeError(
            "At least one scenario did not fail closed."
        )

    historical_verifier_mode_after = (
        mode_bits(
            HISTORICAL_VERIFIER
        )
    )

    if (
        historical_verifier_mode_after
        != historical_verifier_mode_before
    ):
        raise RuntimeError(
            "Historical verifier mode was not restored."
        )

    final_control = run_verifier()

    if final_control.returncode != 0:
        raise RuntimeError(
            "Canonical control run failed: "
            + (
                final_control.stderr.strip()
                or final_control.stdout.strip()
            )
        )

    if sha256_file(RESULT) != EXPECTED_RESULT_SHA:
        raise RuntimeError(
            "Canonical authoritative result not restored."
        )

    if (
        sha256_file(HISTORICAL_RESULT)
        != EXPECTED_HISTORICAL_RESULT_SHA
    ):
        raise RuntimeError(
            "Historical Stage387 result not restored."
        )

    if (
        mode_bits(HISTORICAL_VERIFIER)
        != historical_verifier_mode_before
    ):
        raise RuntimeError(
            "Historical verifier mode changed after control run."
        )

    report_payload = {
        "stage": 387,
        "source_stage": 386,
        "report_type":
            "authoritative_interoperability_fail_closed_regression_report",
        "decision":
            "authoritative_fail_closed_regression_verified",
        "verification_status":
            "verified",
        "scenario_count":
            16,
        "passed_scenario_count":
            16,
        "failed_scenario_count":
            0,
        "all_negative_cases_fail_closed":
            True,
        "canonical_restoration_verified":
            True,
        "file_mode_restoration_verified":
            True,
        "historical_verifier_mode_before":
            format(
                historical_verifier_mode_before,
                "o",
            ),
        "historical_verifier_mode_after":
            format(
                historical_verifier_mode_after,
                "o",
            ),
        "canonical_authoritative_result_sha256":
            EXPECTED_RESULT_SHA,
        "historical_stage387_result_sha256":
            EXPECTED_HISTORICAL_RESULT_SHA,
        "historical_stage387_record_rewritten":
            False,
        "scenarios":
            results,
        "security_boundary": {
            "private_key_material_included":
                False,
            "key_seed_material_included":
                False,
            "raw_qkd_secret_material_included":
                False,
            "default_deny_publication_boundary_preserved":
                True,
        },
        "limitations": {
            "entire_system_quantum_safe":
                False,
            "formal_acceptance_eligible":
                False,
            "formal_acceptance_issued":
                False,
            "formal_acceptance":
                False,
            "pipeline_completed":
                False,
            "public_release_allowed":
                False,
            "qkd_hardware_verified":
                False,
        },
    }

    canonical = json.dumps(
        report_payload,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
    ).encode("utf-8")

    payload_sha = sha256_bytes(
        canonical
    )

    report = dict(
        report_payload
    )

    report[
        "report_payload_sha256"
    ] = payload_sha

    raw = (
        json.dumps(
            report,
            indent=2,
            sort_keys=True,
            ensure_ascii=False,
        )
        + "\n"
    ).encode("utf-8")

    REPORT.write_bytes(
        raw
    )

    raw_sha = sha256_bytes(
        raw
    )

    REPORT_SIDECAR.write_text(
        raw_sha
        + "  "
        + str(
            REPORT.relative_to(
                ROOT
            )
        )
        + "\n",
        encoding="utf-8",
    )

    print("stage = 387")
    print(
        "decision = authoritative_fail_closed_regression_verified"
    )
    print(
        "verification_status = verified"
    )
    print(
        "scenario_count = 16"
    )
    print(
        "passed_scenario_count = 16"
    )
    print(
        "failed_scenario_count = 0"
    )
    print(
        "canonical_restoration_verified = true"
    )
    print(
        "file_mode_restoration_verified = true"
    )
    print(
        "historical_verifier_mode_before = "
        + format(
            historical_verifier_mode_before,
            "o",
        )
    )
    print(
        "historical_verifier_mode_after = "
        + format(
            historical_verifier_mode_after,
            "o",
        )
    )
    print(
        "report_payload_sha256 = "
        + payload_sha
    )
    print(
        "report_raw_sha256 = "
        + raw_sha
    )

    return 0


if __name__ == "__main__":
    raise SystemExit(
        main()
    )
