#!/usr/bin/env python3

import json
import subprocess
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]

VERIFIER = (
    ROOT
    / "development/stage387/"
    "verify_stage387_pqc_interoperability.py"
)

POLICY = (
    ROOT
    / "development/stage387/"
    "stage387_pqc_interoperability_policy.json"
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

TARGET = (
    ROOT
    / "docs/final-acceptance-attestation/"
    "stage373_final_acceptance_attestation.json"
)

GO_MOD = (
    ROOT
    / "development/stage387/go.mod"
)


def run_verifier():
    return subprocess.run(
        [
            "python3",
            str(VERIFIER),
        ],
        cwd=ROOT,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )


def decision_from_output(output):
    for line in output.splitlines():
        if line.startswith("decision = "):
            return line.split(
                "decision = ",
                1,
            )[1].strip()

    return None


def backup(backups, path):
    backups[path] = path.read_bytes()


def restore(backups):
    for path, content in backups.items():
        path.write_bytes(content)


def assert_failure_case(
    name,
    mutate,
    expected_decision,
):
    backups = {}

    try:
        mutate(backups)

        proc = run_verifier()

        combined = (
            proc.stdout
            + "\n"
            + proc.stderr
        )

        decision = decision_from_output(
            combined
        )

        if proc.returncode == 0:
            print(
                f"FAIL: {name} unexpectedly succeeded"
            )
            print(combined)
            raise SystemExit(1)

        if decision != expected_decision:
            print(
                f"FAIL: {name}"
            )
            print(
                " expected =",
                expected_decision,
            )
            print(
                " actual   =",
                decision,
            )
            print(combined)
            raise SystemExit(1)

        print(
            f"PASS: {name} -> {decision}"
        )

    finally:
        restore(backups)


def mutate_public_key_missing(backups):
    backup(backups, PUBLIC_KEY)
    PUBLIC_KEY.unlink()


def mutate_pem_hash(backups):
    backup(backups, PUBLIC_KEY)

    data = bytearray(
        PUBLIC_KEY.read_bytes()
    )

    data[-2] ^= 0x01

    PUBLIC_KEY.write_bytes(
        bytes(data)
    )


def mutate_signature(backups):
    backup(backups, SIGNATURE)

    data = bytearray(
        SIGNATURE.read_bytes()
    )

    data[0] ^= 0x01

    SIGNATURE.write_bytes(
        bytes(data)
    )


def mutate_target(backups):
    backup(backups, TARGET)

    data = bytearray(
        TARGET.read_bytes()
    )

    data[-2] ^= 0x01

    TARGET.write_bytes(
        bytes(data)
    )


def mutate_raw_binding(backups):
    backup(backups, POLICY)

    data = json.loads(
        POLICY.read_text(
            encoding="utf-8"
        )
    )

    data["expected"][
        "raw_public_key_sha256"
    ] = "0" * 64

    POLICY.write_text(
        json.dumps(
            data,
            ensure_ascii=False,
            sort_keys=True,
            indent=2,
        )
        + "\n",
        encoding="utf-8",
    )


def mutate_algorithm(backups):
    backup(backups, POLICY)

    data = json.loads(
        POLICY.read_text(
            encoding="utf-8"
        )
    )

    data["algorithm"] = "ML-DSA-44"

    POLICY.write_text(
        json.dumps(
            data,
            ensure_ascii=False,
            sort_keys=True,
            indent=2,
        )
        + "\n",
        encoding="utf-8",
    )


def mutate_context(backups):
    backup(backups, POLICY)

    data = json.loads(
        POLICY.read_text(
            encoding="utf-8"
        )
    )

    data["context_string"] = (
        "QSP-Stage375-v1-modified"
    )

    POLICY.write_text(
        json.dumps(
            data,
            ensure_ascii=False,
            sort_keys=True,
            indent=2,
        )
        + "\n",
        encoding="utf-8",
    )


def mutate_fips_standard(backups):
    backup(backups, POLICY)

    data = json.loads(
        POLICY.read_text(
            encoding="utf-8"
        )
    )

    data["fips_standard"] = "FIPS 999"

    POLICY.write_text(
        json.dumps(
            data,
            ensure_ascii=False,
            sort_keys=True,
            indent=2,
        )
        + "\n",
        encoding="utf-8",
    )


def mutate_source_stage(backups):
    backup(backups, POLICY)

    data = json.loads(
        POLICY.read_text(
            encoding="utf-8"
        )
    )

    data["source_stage"] = 385

    POLICY.write_text(
        json.dumps(
            data,
            ensure_ascii=False,
            sort_keys=True,
            indent=2,
        )
        + "\n",
        encoding="utf-8",
    )


def mutate_secondary_verifier(backups):
    backup(backups, POLICY)

    data = json.loads(
        POLICY.read_text(
            encoding="utf-8"
        )
    )

    data["implementations"][
        "implementation_b"
    ]["name"] = "Unknown Verifier"

    POLICY.write_text(
        json.dumps(
            data,
            ensure_ascii=False,
            sort_keys=True,
            indent=2,
        )
        + "\n",
        encoding="utf-8",
    )


def mutate_circl_policy_version(backups):
    backup(backups, POLICY)

    data = json.loads(
        POLICY.read_text(
            encoding="utf-8"
        )
    )

    data["implementations"][
        "implementation_b"
    ]["version"] = "v1.6.4"

    POLICY.write_text(
        json.dumps(
            data,
            ensure_ascii=False,
            sort_keys=True,
            indent=2,
        )
        + "\n",
        encoding="utf-8",
    )


def mutate_circl_runtime_version(backups):
    backup(backups, GO_MOD)

    text = GO_MOD.read_text(
        encoding="utf-8"
    )

    text = text.replace(
        "github.com/cloudflare/circl v1.6.5",
        "github.com/cloudflare/circl v1.6.3",
    )

    GO_MOD.write_text(
        text,
        encoding="utf-8",
    )


def main():
    baseline = run_verifier()

    if baseline.returncode != 0:
        print(
            "FAIL: Stage387 baseline does not succeed"
        )
        print(baseline.stdout)
        print(baseline.stderr)
        return 1

    baseline_decision = (
        decision_from_output(
            baseline.stdout
        )
    )

    expected_success = (
        "pqc_multi_implementation_"
        "interoperability_verified"
    )

    if baseline_decision != expected_success:
        print(
            "FAIL: unexpected baseline decision"
        )
        return 1

    print(
        "PASS: baseline succeeds ->",
        baseline_decision,
    )

    cases = [
        (
            "public key missing",
            mutate_public_key_missing,
            "fail_closed",
        ),
        (
            "PEM public-key tampering",
            mutate_pem_hash,
            "pqc_public_key_pem_hash_mismatch",
        ),
        (
            "signature tampering",
            mutate_signature,
            "pqc_signature_hash_mismatch",
        ),
        (
            "signed-target tampering",
            mutate_target,
            "pqc_signed_target_hash_mismatch",
        ),
        (
            "raw public-key binding mismatch",
            mutate_raw_binding,
            "pqc_raw_public_key_hash_mismatch",
        ),
        (
            "algorithm downgrade",
            mutate_algorithm,
            "pqc_algorithm_identifier_mismatch",
        ),
        (
            "context mismatch",
            mutate_context,
            "pqc_context_string_mismatch",
        ),
        (
            "FIPS binding mismatch",
            mutate_fips_standard,
            "pqc_fips_standard_mismatch",
        ),
        (
            "source-stage mismatch",
            mutate_source_stage,
            "stage387_source_stage_mismatch",
        ),
        (
            "secondary verifier mismatch",
            mutate_secondary_verifier,
            "pqc_secondary_verifier_mismatch",
        ),
        (
            "CIRCL policy version mismatch",
            mutate_circl_policy_version,
            "pqc_circl_policy_version_mismatch",
        ),
        (
            "CIRCL runtime version mismatch",
            mutate_circl_runtime_version,
            "pqc_circl_runtime_version_mismatch",
        ),
    ]

    for (
        name,
        mutate,
        expected_decision,
    ) in cases:
        assert_failure_case(
            name,
            mutate,
            expected_decision,
        )

    print()
    print(
        "PASS: all Stage387 fail-closed "
        "interoperability tests completed"
    )

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
