#!/usr/bin/env python3
"""
Stage383 Policy-Bound Recovery Orchestration
& Formal Acceptance Eligibility Gate.

This verifier:

- preserves Stage377 through Stage382
- validates the Stage383 development policy and contract
- validates Stage382 policy and SHA-256 binding
- verifies embedded result hashes and file hashes
- rejects mixed or stale upstream artifact bindings
- creates a deterministic recovery-session ID
- remains pending while Stage377 is incomplete
- requires Stage378 through Stage382 reverification after Stage377 completion
- reports formal_acceptance_eligible only when every required condition passes
- never issues formal acceptance
- never declares pipeline completion
- never creates a replacement timestamp proof
"""

from __future__ import annotations

import hashlib
import json
import sys
from pathlib import Path
from typing import Any


STAGE = 383

DEVELOPMENT_POLICY_PATH = Path(
    ".stage383-development-policy.json"
)

CONTRACT_PATH = Path(
    "development/stage383/"
    "stage383_recovery_orchestration_contract.json"
)

CONTRACT_SHA256_PATH = Path(
    "development/stage383/"
    "stage383_recovery_orchestration_contract.sha256"
)

STAGE377_RESULT_PATH = Path(
    "docs/timestamp-finalization/"
    "stage377_dual_timestamp_finalization_result.json"
)

STAGE378_RESULT_PATH = Path(
    "docs/qkd/"
    "stage378_qkd_safety_metadata_binding_result.json"
)

STAGE379_RESULT_PATH = Path(
    "development/stage379/"
    "stage379_scoped_total_verification_result.json"
)

STAGE380_RESULT_PATH = Path(
    "development/stage380/"
    "stage380_independent_verification_result.json"
)

STAGE381_RESULT_PATH = Path(
    "docs/verification/stage381/"
    "stage381_cross_platform_verification_package_result.json"
)

STAGE382_POLICY_PATH = Path(
    "development/stage382/policy-profiles/"
    "qsp-dual-timestamp-final-acceptance-v1.json"
)

STAGE382_POLICY_SHA256_PATH = Path(
    "development/stage382/policy-profiles/"
    "qsp-dual-timestamp-final-acceptance-v1.sha256"
)

STAGE382_RESULT_PATH = Path(
    "development/stage382/"
    "stage382_upstream_finalization_result.json"
)

STAGE382_MANIFEST_PATH = Path(
    "development/stage382/"
    "stage382_policy_activation_manifest.json"
)

OUTPUT_PATH = Path(
    "development/stage383/"
    "stage383_formal_acceptance_eligibility_result.json"
)


REQUIRED_ORDER = [
    "stage377",
    "stage378",
    "stage379",
    "stage380",
    "stage381",
    "stage382",
    "stage383",
]


def load_json(path: Path) -> dict[str, Any]:
    data = json.loads(path.read_text(encoding="utf-8"))

    if not isinstance(data, dict):
        raise TypeError(
            f"JSON root must be an object: {path}"
        )

    return data


def canonical_json_bytes(value: Any) -> bytes:
    return json.dumps(
        value,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")


def sha256_bytes(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def sha256_file(path: Path) -> str:
    return sha256_bytes(path.read_bytes())


def embedded_hash(
    data: dict[str, Any],
    field_name: str,
) -> str:
    payload = dict(data)
    payload.pop(field_name, None)

    return sha256_bytes(
        canonical_json_bytes(payload)
    )


def parse_sha256_record(
    path: Path,
) -> tuple[str, str]:
    parts = path.read_text(
        encoding="utf-8"
    ).strip().split(maxsplit=1)

    if len(parts) != 2:
        raise ValueError(
            f"invalid SHA-256 record format: {path}"
        )

    return parts[0], parts[1]


def add_check(
    checks: list[dict[str, Any]],
    *,
    name: str,
    passed: bool,
    expected: Any,
    actual: Any,
    critical: bool,
    category: str,
) -> None:
    checks.append(
        {
            "name": name,
            "category": category,
            "critical": critical,
            "passed": bool(passed),
            "expected": expected,
            "actual": actual,
        }
    )


def find_named_check(
    data: dict[str, Any],
    name: str,
) -> bool | None:
    checks = data.get("checks")

    if not isinstance(checks, list):
        return None

    for check in checks:
        if not isinstance(check, dict):
            continue

        if check.get("name") == name:
            value = check.get("passed")

            if isinstance(value, bool):
                return value

    return None


def stage379_critical_integrity(
    stage379: dict[str, Any],
) -> bool:
    direct = stage379.get(
        "critical_integrity_valid"
    )

    if isinstance(direct, bool):
        return direct

    named = find_named_check(
        stage379,
        "critical_integrity_valid",
    )

    if isinstance(named, bool):
        return named

    named = find_named_check(
        stage379,
        "critical_integrity_validated",
    )

    if isinstance(named, bool):
        return named

    return False


def deterministic_recovery_session(
    *,
    stage377_file_sha256: str,
    stage382_policy_sha256: str,
    contract_sha256: str,
) -> tuple[str, dict[str, str]]:
    components = {
        "stage377_result_sha256":
            stage377_file_sha256,
        "stage382_policy_sha256":
            stage382_policy_sha256,
        "contract_sha256":
            contract_sha256,
    }

    digest = sha256_bytes(
        canonical_json_bytes(components)
    )

    return (
        "stage383-" + digest,
        components,
    )


def main() -> int:
    checks: list[dict[str, Any]] = []
    errors: list[str] = []

    try:
        required_files = (
            DEVELOPMENT_POLICY_PATH,
            CONTRACT_PATH,
            CONTRACT_SHA256_PATH,
            STAGE377_RESULT_PATH,
            STAGE378_RESULT_PATH,
            STAGE379_RESULT_PATH,
            STAGE380_RESULT_PATH,
            STAGE381_RESULT_PATH,
            STAGE382_POLICY_PATH,
            STAGE382_POLICY_SHA256_PATH,
            STAGE382_RESULT_PATH,
            STAGE382_MANIFEST_PATH,
        )

        for required_file in required_files:
            present = required_file.is_file()

            add_check(
                checks,
                name=(
                    "required_file_present:"
                    + required_file.as_posix()
                ),
                passed=present,
                expected=True,
                actual=present,
                critical=True,
                category="integrity",
            )

        missing_files = [
            path
            for path in required_files
            if not path.is_file()
        ]

        if missing_files:
            raise FileNotFoundError(
                "missing required file(s): "
                + ", ".join(
                    path.as_posix()
                    for path in missing_files
                )
            )

        development_policy = load_json(
            DEVELOPMENT_POLICY_PATH
        )
        contract = load_json(
            CONTRACT_PATH
        )
        stage377 = load_json(
            STAGE377_RESULT_PATH
        )
        stage378 = load_json(
            STAGE378_RESULT_PATH
        )
        stage379 = load_json(
            STAGE379_RESULT_PATH
        )
        stage380 = load_json(
            STAGE380_RESULT_PATH
        )
        stage381 = load_json(
            STAGE381_RESULT_PATH
        )
        stage382_policy = load_json(
            STAGE382_POLICY_PATH
        )
        stage382_result = load_json(
            STAGE382_RESULT_PATH
        )
        stage382_manifest = load_json(
            STAGE382_MANIFEST_PATH
        )

        file_hashes = {
            "stage377":
                sha256_file(STAGE377_RESULT_PATH),
            "stage378":
                sha256_file(STAGE378_RESULT_PATH),
            "stage379":
                sha256_file(STAGE379_RESULT_PATH),
            "stage380":
                sha256_file(STAGE380_RESULT_PATH),
            "stage381":
                sha256_file(STAGE381_RESULT_PATH),
            "stage382_policy":
                sha256_file(STAGE382_POLICY_PATH),
            "stage382_result":
                sha256_file(STAGE382_RESULT_PATH),
            "stage382_manifest":
                sha256_file(STAGE382_MANIFEST_PATH),
            "stage383_contract":
                sha256_file(CONTRACT_PATH),
        }

        embedded_hashes = {
            "stage377": embedded_hash(
                stage377,
                "result_sha256",
            ),
            "stage378": embedded_hash(
                stage378,
                "result_sha256",
            ),
            "stage379": embedded_hash(
                stage379,
                "result_sha256",
            ),
            "stage380": embedded_hash(
                stage380,
                "result_sha256",
            ),
            "stage381": embedded_hash(
                stage381,
                "result_sha256",
            ),
            "stage382_result": embedded_hash(
                stage382_result,
                "result_sha256",
            ),
            "stage382_manifest": embedded_hash(
                stage382_manifest,
                "manifest_sha256",
            ),
        }

        # ----------------------------------------------------
        # Development policy and contract validation
        # ----------------------------------------------------

        add_check(
            checks,
            name="development_policy_stage_valid",
            passed=(
                development_policy.get("stage")
                == STAGE
            ),
            expected=STAGE,
            actual=development_policy.get("stage"),
            critical=True,
            category="policy",
        )

        add_check(
            checks,
            name="development_policy_source_stage_valid",
            passed=(
                development_policy.get(
                    "source_stage"
                )
                == 382
            ),
            expected=382,
            actual=development_policy.get(
                "source_stage"
            ),
            critical=True,
            category="policy",
        )

        add_check(
            checks,
            name="development_policy_required_order_valid",
            passed=(
                development_policy.get(
                    "required_reverification_order"
                )
                == REQUIRED_ORDER
            ),
            expected=REQUIRED_ORDER,
            actual=development_policy.get(
                "required_reverification_order"
            ),
            critical=True,
            category="policy",
        )

        policy_requirements = (
            development_policy.get(
                "requirements",
                {},
            )
        )

        add_check(
            checks,
            name="new_timestamp_proof_generation_forbidden",
            passed=(
                policy_requirements.get(
                    "new_timestamp_proof_generation_allowed"
                )
                is False
            ),
            expected=False,
            actual=policy_requirements.get(
                "new_timestamp_proof_generation_allowed"
            ),
            critical=True,
            category="safety",
        )

        add_check(
            checks,
            name="automatic_formal_acceptance_issuance_forbidden",
            passed=(
                policy_requirements.get(
                    "automatic_formal_acceptance_issuance_allowed"
                )
                is False
            ),
            expected=False,
            actual=policy_requirements.get(
                "automatic_formal_acceptance_issuance_allowed"
            ),
            critical=True,
            category="safety",
        )

        add_check(
            checks,
            name="mixed_workflow_artifacts_forbidden",
            passed=(
                policy_requirements.get(
                    "mixed_workflow_run_artifacts_allowed"
                )
                is False
            ),
            expected=False,
            actual=policy_requirements.get(
                "mixed_workflow_run_artifacts_allowed"
            ),
            critical=True,
            category="safety",
        )

        add_check(
            checks,
            name="stage_skip_forbidden",
            passed=(
                policy_requirements.get(
                    "stage_skip_allowed"
                )
                is False
            ),
            expected=False,
            actual=policy_requirements.get(
                "stage_skip_allowed"
            ),
            critical=True,
            category="safety",
        )

        add_check(
            checks,
            name="contract_stage_valid",
            passed=contract.get("stage") == STAGE,
            expected=STAGE,
            actual=contract.get("stage"),
            critical=True,
            category="contract",
        )

        add_check(
            checks,
            name="contract_source_stage_valid",
            passed=(
                contract.get("source_stage") == 382
            ),
            expected=382,
            actual=contract.get("source_stage"),
            critical=True,
            category="contract",
        )

        add_check(
            checks,
            name="contract_required_order_valid",
            passed=(
                contract.get(
                    "required_reverification_order"
                )
                == REQUIRED_ORDER
            ),
            expected=REQUIRED_ORDER,
            actual=contract.get(
                "required_reverification_order"
            ),
            critical=True,
            category="contract",
        )

        contract_record_hash, contract_record_path = (
            parse_sha256_record(
                CONTRACT_SHA256_PATH
            )
        )

        add_check(
            checks,
            name="contract_sha256_valid",
            passed=(
                contract_record_hash
                == file_hashes["stage383_contract"]
            ),
            expected=file_hashes[
                "stage383_contract"
            ],
            actual=contract_record_hash,
            critical=True,
            category="integrity",
        )

        add_check(
            checks,
            name="contract_sha256_record_path_valid",
            passed=(
                contract_record_path
                == CONTRACT_PATH.as_posix()
            ),
            expected=CONTRACT_PATH.as_posix(),
            actual=contract_record_path,
            critical=True,
            category="integrity",
        )

        # ----------------------------------------------------
        # Stage382 policy binding validation
        # ----------------------------------------------------

        stage382_policy_record_hash, (
            stage382_policy_record_path
        ) = parse_sha256_record(
            STAGE382_POLICY_SHA256_PATH
        )

        add_check(
            checks,
            name="stage382_policy_sha256_valid",
            passed=(
                stage382_policy_record_hash
                == file_hashes["stage382_policy"]
            ),
            expected=file_hashes[
                "stage382_policy"
            ],
            actual=stage382_policy_record_hash,
            critical=True,
            category="integrity",
        )

        add_check(
            checks,
            name="stage382_policy_sha256_record_path_valid",
            passed=(
                stage382_policy_record_path
                == STAGE382_POLICY_PATH.as_posix()
            ),
            expected=STAGE382_POLICY_PATH.as_posix(),
            actual=stage382_policy_record_path,
            critical=True,
            category="integrity",
        )

        add_check(
            checks,
            name="stage382_policy_profile_name_valid",
            passed=(
                stage382_policy.get(
                    "profile_name"
                )
                == (
                    "qsp-dual-timestamp-"
                    "final-acceptance-v1"
                )
            ),
            expected=(
                "qsp-dual-timestamp-"
                "final-acceptance-v1"
            ),
            actual=stage382_policy.get(
                "profile_name"
            ),
            critical=True,
            category="policy",
        )

        # ----------------------------------------------------
        # Embedded result-hash validation
        # ----------------------------------------------------

        result_objects = {
            "stage377": stage377,
            "stage378": stage378,
            "stage379": stage379,
            "stage380": stage380,
            "stage381": stage381,
            "stage382_result": stage382_result,
        }

        # Stage380 through Stage382 use the canonical JSON
        # self-hash method reproduced by this verifier.
        #
        # Stage377 through Stage379 were generated by inherited
        # stage-specific hash writers. Their declared self-hashes
        # must not be recomputed with the newer Stage380+ method.
        # They are instead validated through:
        #
        # 1. strict SHA-256 hexadecimal format
        # 2. the current file SHA-256
        # 3. the Stage382 manifest file-SHA-256 binding
        # 4. the Stage382 manifest embedded-hash binding
        # 5. the independently validated Stage382 manifest hash
        #
        # This preserves the original stage-specific semantics
        # without weakening the integrity chain.

        legacy_self_hash_stages = (
            "stage377",
            "stage378",
            "stage379",
        )

        for name in legacy_self_hash_stages:
            declared = result_objects[
                name
            ].get("result_sha256")

            well_formed = (
                isinstance(declared, str)
                and len(declared) == 64
                and all(
                    character in "0123456789abcdef"
                    for character in declared
                )
            )

            add_check(
                checks,
                name=(
                    f"{name}_declared_result_sha256_"
                    "well_formed"
                ),
                passed=well_formed,
                expected=(
                    "64-character lowercase "
                    "hexadecimal SHA-256"
                ),
                actual=declared,
                critical=True,
                category="integrity",
            )

        canonical_self_hash_stages = (
            "stage380",
            "stage381",
            "stage382_result",
        )

        for name in canonical_self_hash_stages:
            data = result_objects[name]
            declared = data.get("result_sha256")
            actual = embedded_hashes[name]

            add_check(
                checks,
                name=(
                    f"{name}_embedded_result_sha256_valid"
                ),
                passed=declared == actual,
                expected=actual,
                actual=declared,
                critical=True,
                category="integrity",
            )

        add_check(
            checks,
            name="stage382_manifest_embedded_sha256_valid",
            passed=(
                stage382_manifest.get(
                    "manifest_sha256"
                )
                == embedded_hashes[
                    "stage382_manifest"
                ]
            ),
            expected=embedded_hashes[
                "stage382_manifest"
            ],
            actual=stage382_manifest.get(
                "manifest_sha256"
            ),
            critical=True,
            category="integrity",
        )

        # ----------------------------------------------------
        # Stage382 manifest/current-file consistency
        # ----------------------------------------------------

        manifest_bindings = (
            stage382_manifest.get(
                "upstream_bindings",
                {},
            )
        )

        for stage_name in (
            "stage377",
            "stage378",
            "stage379",
            "stage380",
            "stage381",
        ):
            binding = manifest_bindings.get(
                stage_name,
                {},
            )

            add_check(
                checks,
                name=(
                    f"{stage_name}_manifest_file_sha256_matches"
                ),
                passed=(
                    binding.get("file_sha256")
                    == file_hashes[stage_name]
                ),
                expected=file_hashes[stage_name],
                actual=binding.get("file_sha256"),
                critical=True,
                category="session_binding",
            )

            add_check(
                checks,
                name=(
                    f"{stage_name}_manifest_embedded_sha256_matches"
                ),
                passed=(
                    binding.get(
                        "embedded_result_sha256"
                    )
                    == result_objects[
                        stage_name
                    ].get("result_sha256")
                ),
                expected=result_objects[
                    stage_name
                ].get("result_sha256"),
                actual=binding.get(
                    "embedded_result_sha256"
                ),
                critical=True,
                category="session_binding",
            )

        manifest_stage382_result = (
            stage382_manifest.get(
                "stage382_result",
                {},
            )
        )

        add_check(
            checks,
            name="stage382_manifest_result_file_sha256_matches",
            passed=(
                manifest_stage382_result.get(
                    "file_sha256"
                )
                == file_hashes["stage382_result"]
            ),
            expected=file_hashes[
                "stage382_result"
            ],
            actual=manifest_stage382_result.get(
                "file_sha256"
            ),
            critical=True,
            category="session_binding",
        )

        add_check(
            checks,
            name="stage382_manifest_result_embedded_sha256_matches",
            passed=(
                manifest_stage382_result.get(
                    "embedded_result_sha256"
                )
                == stage382_result.get(
                    "result_sha256"
                )
            ),
            expected=stage382_result.get(
                "result_sha256"
            ),
            actual=manifest_stage382_result.get(
                "embedded_result_sha256"
            ),
            critical=True,
            category="session_binding",
        )

        stage382_result_policy = (
            stage382_result.get(
                "policy_profile",
                {},
            )
        )
        stage382_manifest_policy = (
            stage382_manifest.get(
                "policy_profile",
                {},
            )
        )

        for source_name, policy_binding in (
            (
                "stage382_result",
                stage382_result_policy,
            ),
            (
                "stage382_manifest",
                stage382_manifest_policy,
            ),
        ):
            add_check(
                checks,
                name=(
                    f"{source_name}_policy_name_matches"
                ),
                passed=(
                    policy_binding.get("name")
                    == stage382_policy.get(
                        "profile_name"
                    )
                ),
                expected=stage382_policy.get(
                    "profile_name"
                ),
                actual=policy_binding.get("name"),
                critical=True,
                category="policy_binding",
            )

            add_check(
                checks,
                name=(
                    f"{source_name}_policy_sha256_matches"
                ),
                passed=(
                    policy_binding.get("sha256")
                    == file_hashes[
                        "stage382_policy"
                    ]
                ),
                expected=file_hashes[
                    "stage382_policy"
                ],
                actual=policy_binding.get(
                    "sha256"
                ),
                critical=True,
                category="policy_binding",
            )

        # ----------------------------------------------------
        # Deterministic recovery-session ID
        # ----------------------------------------------------

        recovery_session_id, (
            recovery_session_components
        ) = deterministic_recovery_session(
            stage377_file_sha256=(
                file_hashes["stage377"]
            ),
            stage382_policy_sha256=(
                file_hashes["stage382_policy"]
            ),
            contract_sha256=(
                file_hashes["stage383_contract"]
            ),
        )

        # ----------------------------------------------------
        # Stage377 completion observation
        # ----------------------------------------------------

        stage377_complete_checks = {
            "stage377_stage_valid":
                stage377.get("stage") == 377,

            "stage377_decision_complete":
                stage377.get("decision")
                == (
                    "dual_timestamp_"
                    "final_acceptance_verified"
                ),

            "stage377_verified_proof_count_complete":
                stage377.get(
                    "verified_proof_count"
                )
                == 2,

            "stage377_effective_final_acceptance_complete":
                stage377.get(
                    "effective_final_acceptance"
                )
                is True,

            "stage377_timestamp_verified":
                stage377.get(
                    "timestamp_verified"
                )
                is True,

            "stage377_rfc3161_verified":
                stage377.get(
                    "rfc3161_verified"
                )
                is True,

            "stage377_opentimestamps_verified":
                stage377.get(
                    "opentimestamps_verified"
                )
                is True,
        }

        for name, passed in (
            stage377_complete_checks.items()
        ):
            add_check(
                checks,
                name=name,
                passed=passed,
                expected=True,
                actual=passed,
                critical=False,
                category="eligibility",
            )

        stage377_complete = all(
            stage377_complete_checks.values()
        )

        # ----------------------------------------------------
        # Downstream eligibility conditions
        # ----------------------------------------------------

        forbidden_public_files = (
            stage378.get(
                "forbidden_public_files",
                [],
            )
        )

        if not isinstance(
            forbidden_public_files,
            list,
        ):
            forbidden_public_files = [
                "invalid_forbidden_public_files_type"
            ]

        stage378_ready_checks = {
            "stage378_stage_valid":
                stage378.get("stage") == 378,

            "stage378_stage377_hash_valid":
                stage378.get(
                    "stage377_hash_valid"
                )
                is True,

            "stage378_stage377_final_acceptance_verified":
                stage378.get(
                    "stage377_final_acceptance_verified"
                )
                is True,

            "stage378_qkd_metadata_bound":
                stage378.get(
                    "qkd_metadata_bound"
                )
                is True,

            "stage378_raw_qkd_key_not_published":
                stage378.get(
                    "raw_qkd_key_publication_detected"
                )
                is False,

            "stage378_private_material_not_detected":
                stage378.get(
                    "private_material_content_detected"
                )
                is False,

            "stage378_forbidden_public_files_empty":
                len(forbidden_public_files)
                == 0,
        }

        for name, passed in (
            stage378_ready_checks.items()
        ):
            is_safety = name in {
                "stage378_raw_qkd_key_not_published",
                "stage378_private_material_not_detected",
                "stage378_forbidden_public_files_empty",
            }

            add_check(
                checks,
                name=name,
                passed=passed,
                expected=True,
                actual=passed,
                critical=is_safety,
                category=(
                    "safety"
                    if is_safety
                    else "eligibility"
                ),
            )

        stage378_ready = all(
            stage378_ready_checks.values()
        )

        stage379_integrity = (
            stage379_critical_integrity(stage379)
        )

        stage379_ready_checks = {
            "stage379_stage_valid":
                stage379.get("stage") == 379,

            "stage379_formal_acceptance":
                stage379.get(
                    "formal_acceptance"
                )
                is True,

            "stage379_pipeline_completed":
                stage379.get(
                    "pipeline_completed"
                )
                is True,

            "stage379_critical_integrity_valid":
                stage379_integrity is True,
        }

        for name, passed in (
            stage379_ready_checks.items()
        ):
            add_check(
                checks,
                name=name,
                passed=passed,
                expected=True,
                actual=passed,
                critical=False,
                category="eligibility",
            )

        stage379_ready = all(
            stage379_ready_checks.values()
        )

        stage380_ready_checks = {
            "stage380_stage_valid":
                stage380.get("stage") == 380,

            "stage380_package_integrity_verified":
                stage380.get(
                    "package_integrity_verified"
                )
                is True,

            "stage380_formal_independent_verification":
                stage380.get(
                    "formal_independent_verification"
                )
                is True,

            "stage380_critical_failure_count_zero":
                stage380.get(
                    "critical_failure_count"
                )
                == 0,
        }

        for name, passed in (
            stage380_ready_checks.items()
        ):
            add_check(
                checks,
                name=name,
                passed=passed,
                expected=True,
                actual=passed,
                critical=(
                    name
                    in {
                        "stage380_package_integrity_verified",
                        "stage380_critical_failure_count_zero",
                    }
                ),
                category=(
                    "integrity"
                    if name
                    in {
                        "stage380_package_integrity_verified",
                        "stage380_critical_failure_count_zero",
                    }
                    else "eligibility"
                ),
            )

        stage380_ready = all(
            stage380_ready_checks.values()
        )

        stage381_ready_checks = {
            "stage381_stage_valid":
                stage381.get("stage") == 381,

            "stage381_package_integrity_verified":
                stage381.get(
                    "package_integrity_verified"
                )
                is True,

            "stage381_cross_platform_reverification_verified":
                stage381.get(
                    "cross_platform_reverification_verified"
                )
                is True,

            "stage381_same_input_same_output_verified":
                stage381.get(
                    "same_input_same_output_verified"
                )
                is True,

            "stage381_same_decision_verified":
                stage381.get(
                    "same_decision_verified"
                )
                is True,

            "stage381_same_exit_code_verified":
                stage381.get(
                    "same_exit_code_verified"
                )
                is True,

            "stage381_same_stage380_result_sha256_verified":
                stage381.get(
                    "same_stage380_result_sha256_verified"
                )
                is True,

            "stage381_same_canonical_result_sha256_verified":
                stage381.get(
                    "same_canonical_result_sha256_verified"
                )
                is True,

            "stage381_critical_failure_count_zero":
                stage381.get(
                    "critical_failure_count"
                )
                == 0,
        }

        for name, passed in (
            stage381_ready_checks.items()
        ):
            add_check(
                checks,
                name=name,
                passed=passed,
                expected=True,
                actual=passed,
                critical=(
                    name
                    in {
                        "stage381_package_integrity_verified",
                        "stage381_critical_failure_count_zero",
                    }
                ),
                category=(
                    "integrity"
                    if name
                    in {
                        "stage381_package_integrity_verified",
                        "stage381_critical_failure_count_zero",
                    }
                    else "eligibility"
                ),
            )

        stage381_ready = all(
            stage381_ready_checks.values()
        )

        stage382_upstream_state = (
            stage382_result.get(
                "upstream_state",
                {},
            )
        )
        stage382_downstream = (
            stage382_result.get(
                "downstream_observation",
                {},
            )
        )
        stage382_activation = (
            stage382_result.get(
                "policy_activation_state",
                {},
            )
        )

        stage382_ready_checks = {
            "stage382_stage_valid":
                stage382_result.get("stage")
                == 382,

            "stage382_policy_activated":
                stage382_activation.get(
                    "policy_activated"
                )
                is True,

            "stage382_stage377_complete":
                stage382_upstream_state.get(
                    "stage377_complete"
                )
                is True,

            "stage382_stage378_ready":
                stage382_downstream.get(
                    "stage378_ready"
                )
                is True,

            "stage382_critical_failure_count_zero":
                stage382_result.get(
                    "critical_failure_count"
                )
                == 0,

            "stage382_automatic_acceptance_not_performed":
                stage382_activation.get(
                    "automatic_acceptance_upgrade_performed"
                )
                is False,

            "stage382_new_timestamp_proof_not_generated":
                stage382_activation.get(
                    "new_timestamp_proof_generated"
                )
                is False,
        }

        for name, passed in (
            stage382_ready_checks.items()
        ):
            is_integrity = name in {
                "stage382_critical_failure_count_zero",
                "stage382_automatic_acceptance_not_performed",
                "stage382_new_timestamp_proof_not_generated",
            }

            add_check(
                checks,
                name=name,
                passed=passed,
                expected=True,
                actual=passed,
                critical=is_integrity,
                category=(
                    "safety"
                    if is_integrity
                    else "eligibility"
                ),
            )

        stage382_ready = all(
            stage382_ready_checks.values()
        )

        # ----------------------------------------------------
        # Final decision
        # ----------------------------------------------------

        critical_failures = sorted(
            check["name"]
            for check in checks
            if (
                check["critical"]
                and not check["passed"]
            )
        )

        eligibility_failures = sorted(
            check["name"]
            for check in checks
            if (
                check["category"]
                == "eligibility"
                and not check["passed"]
            )
        )

        if critical_failures:
            decision = "fail_closed"
            verification_status = (
                "critical_integrity_failure"
            )
            recovery_phase = (
                "integrity_validation_failed"
            )
            formal_acceptance_eligible = False
            exit_code = 2

        elif not stage377_complete:
            decision = (
                "upstream_finalization_pending"
            )
            verification_status = (
                "verified_pending_upstream"
            )
            recovery_phase = (
                "waiting_for_stage377"
            )
            formal_acceptance_eligible = False
            exit_code = 0

        elif not all(
            (
                stage378_ready,
                stage379_ready,
                stage380_ready,
                stage381_ready,
                stage382_ready,
            )
        ):
            decision = "fail_closed"
            verification_status = (
                "verified_not_eligible"
            )
            recovery_phase = (
                "downstream_reverification_required"
            )
            formal_acceptance_eligible = False
            exit_code = 1

        else:
            decision = (
                "formal_acceptance_eligible"
            )
            verification_status = (
                "eligibility_verified"
            )
            recovery_phase = (
                "eligibility_verified"
            )
            formal_acceptance_eligible = True
            exit_code = 0

        result_without_hash: dict[str, Any] = {
            "stage": STAGE,
            "source_stage": 382,
            "engine": (
                "Stage383 Policy-Bound Recovery "
                "Orchestration & Formal Acceptance "
                "Eligibility Gate"
            ),
            "execution_mode": "development",
            "development_only": True,
            "verification_mode": (
                "policy_bound_recovery_orchestration_"
                "and_formal_acceptance_eligibility"
            ),
            "network_access_required": False,
            "fail_closed": True,
            "decision": decision,
            "verification_status":
                verification_status,
            "recovery_phase": recovery_phase,
            "formal_acceptance_eligible":
                formal_acceptance_eligible,
            "formal_acceptance_issued": False,
            "formal_acceptance": False,
            "pipeline_completed": False,
            "public_release_allowed": False,
            "manual_or_verified_issuance_transition_required":
                True,
            "recovery_session": {
                "session_id":
                    recovery_session_id,
                "deterministic": True,
                "components":
                    recovery_session_components,
                "required_order":
                    REQUIRED_ORDER,
                "mixed_workflow_run_artifacts_allowed":
                    False,
                "stage_skip_allowed": False,
                "out_of_order_execution_allowed":
                    False,
            },
            "contract": {
                "path":
                    CONTRACT_PATH.as_posix(),
                "file_sha256":
                    file_hashes[
                        "stage383_contract"
                    ],
                "sha256_record_path":
                    CONTRACT_SHA256_PATH.as_posix(),
                "name":
                    contract.get(
                        "contract_name"
                    ),
                "version":
                    contract.get(
                        "contract_version"
                    ),
            },
            "policy_profile": {
                "name":
                    stage382_policy.get(
                        "profile_name"
                    ),
                "version":
                    stage382_policy.get(
                        "profile_version"
                    ),
                "path":
                    STAGE382_POLICY_PATH.as_posix(),
                "sha256":
                    file_hashes[
                        "stage382_policy"
                    ],
                "sha256_record_path":
                    STAGE382_POLICY_SHA256_PATH.as_posix(),
            },
            "upstream_state": {
                "stage377_complete":
                    stage377_complete,
                "stage377_decision":
                    stage377.get("decision"),
                "stage377_verified_proof_count":
                    stage377.get(
                        "verified_proof_count"
                    ),
                "stage377_effective_final_acceptance":
                    stage377.get(
                        "effective_final_acceptance"
                    ),
                "stage377_file_sha256":
                    file_hashes["stage377"],
                "stage377_embedded_result_sha256":
                    stage377.get(
                        "result_sha256"
                    ),
            },
            "reverification_state": {
                "stage378_ready":
                    stage378_ready,
                "stage379_ready":
                    stage379_ready,
                "stage380_ready":
                    stage380_ready,
                "stage381_ready":
                    stage381_ready,
                "stage382_ready":
                    stage382_ready,
                "all_required_stages_reverified":
                    all(
                        (
                            stage377_complete,
                            stage378_ready,
                            stage379_ready,
                            stage380_ready,
                            stage381_ready,
                            stage382_ready,
                        )
                    ),
            },
            "input_bindings": {
                "stage377": {
                    "path":
                        STAGE377_RESULT_PATH.as_posix(),
                    "file_sha256":
                        file_hashes["stage377"],
                    "embedded_result_sha256":
                        stage377.get(
                            "result_sha256"
                        ),
                },
                "stage378": {
                    "path":
                        STAGE378_RESULT_PATH.as_posix(),
                    "file_sha256":
                        file_hashes["stage378"],
                    "embedded_result_sha256":
                        stage378.get(
                            "result_sha256"
                        ),
                },
                "stage379": {
                    "path":
                        STAGE379_RESULT_PATH.as_posix(),
                    "file_sha256":
                        file_hashes["stage379"],
                    "embedded_result_sha256":
                        stage379.get(
                            "result_sha256"
                        ),
                },
                "stage380": {
                    "path":
                        STAGE380_RESULT_PATH.as_posix(),
                    "file_sha256":
                        file_hashes["stage380"],
                    "embedded_result_sha256":
                        stage380.get(
                            "result_sha256"
                        ),
                },
                "stage381": {
                    "path":
                        STAGE381_RESULT_PATH.as_posix(),
                    "file_sha256":
                        file_hashes["stage381"],
                    "embedded_result_sha256":
                        stage381.get(
                            "result_sha256"
                        ),
                },
                "stage382_result": {
                    "path":
                        STAGE382_RESULT_PATH.as_posix(),
                    "file_sha256":
                        file_hashes[
                            "stage382_result"
                        ],
                    "embedded_result_sha256":
                        stage382_result.get(
                            "result_sha256"
                        ),
                },
                "stage382_manifest": {
                    "path":
                        STAGE382_MANIFEST_PATH.as_posix(),
                    "file_sha256":
                        file_hashes[
                            "stage382_manifest"
                        ],
                    "embedded_manifest_sha256":
                        stage382_manifest.get(
                            "manifest_sha256"
                        ),
                },
            },
            "check_count": len(checks),
            "critical_failure_count":
                len(critical_failures),
            "critical_failures":
                critical_failures,
            "eligibility_failure_count":
                len(eligibility_failures),
            "eligibility_failures":
                eligibility_failures,
            "checks": sorted(
                checks,
                key=lambda item: item["name"],
            ),
            "errors": errors,
            "statement": (
                "Stage383 verifies one deterministic, "
                "policy-bound recovery session across "
                "Stage377 through Stage382. It does not "
                "issue formal acceptance, declare pipeline "
                "completion, generate a replacement "
                "timestamp proof, or overwrite an upstream "
                "record."
            ),
        }

        result_hash = sha256_bytes(
            canonical_json_bytes(
                result_without_hash
            )
        )

        result = dict(result_without_hash)
        result["result_sha256"] = result_hash

        OUTPUT_PATH.parent.mkdir(
            parents=True,
            exist_ok=True,
        )

        OUTPUT_PATH.write_text(
            json.dumps(
                result,
                ensure_ascii=False,
                indent=2,
                sort_keys=True,
            )
            + "\n",
            encoding="utf-8",
            newline="\n",
        )

        print(f"decision={decision}")
        print(
            "verification_status="
            + verification_status
        )
        print(
            "recovery_phase="
            + recovery_phase
        )
        print(
            "recovery_session_id="
            + recovery_session_id
        )
        print(
            "stage377_complete="
            + str(stage377_complete).lower()
        )
        print(
            "stage377_verified_proof_count="
            + str(
                stage377.get(
                    "verified_proof_count"
                )
            )
        )
        print(
            "formal_acceptance_eligible="
            + str(
                formal_acceptance_eligible
            ).lower()
        )
        print(
            "formal_acceptance_issued=false"
        )
        print(
            "critical_failure_count="
            + str(len(critical_failures))
        )
        print(
            "eligibility_failure_count="
            + str(len(eligibility_failures))
        )
        print(
            "result_sha256="
            + result_hash
        )
        print(
            "result_path="
            + OUTPUT_PATH.as_posix()
        )

        return exit_code

    except (
        FileNotFoundError,
        PermissionError,
        json.JSONDecodeError,
        OSError,
        TypeError,
        ValueError,
    ) as exc:
        errors.append(
            f"{type(exc).__name__}: {exc}"
        )

        error_result_without_hash: dict[str, Any] = {
            "stage": STAGE,
            "source_stage": 382,
            "engine": (
                "Stage383 Policy-Bound Recovery "
                "Orchestration & Formal Acceptance "
                "Eligibility Gate"
            ),
            "execution_mode": "development",
            "development_only": True,
            "verification_mode": (
                "policy_bound_recovery_orchestration_"
                "and_formal_acceptance_eligibility"
            ),
            "network_access_required": False,
            "fail_closed": True,
            "decision": "fail_closed",
            "verification_status": "error",
            "recovery_phase": "execution_error",
            "formal_acceptance_eligible": False,
            "formal_acceptance_issued": False,
            "formal_acceptance": False,
            "pipeline_completed": False,
            "public_release_allowed": False,
            "critical_failure_count": 1,
            "critical_failures": [
                "stage383_execution_error"
            ],
            "eligibility_failure_count": 0,
            "eligibility_failures": [],
            "checks": sorted(
                checks,
                key=lambda item: item["name"],
            ),
            "errors": errors,
        }

        error_hash = sha256_bytes(
            canonical_json_bytes(
                error_result_without_hash
            )
        )

        error_result = dict(
            error_result_without_hash
        )
        error_result["result_sha256"] = (
            error_hash
        )

        OUTPUT_PATH.parent.mkdir(
            parents=True,
            exist_ok=True,
        )

        OUTPUT_PATH.write_text(
            json.dumps(
                error_result,
                ensure_ascii=False,
                indent=2,
                sort_keys=True,
            )
            + "\n",
            encoding="utf-8",
            newline="\n",
        )

        print(
            "decision=fail_closed",
            file=sys.stderr,
        )
        print(
            "verification_status=error",
            file=sys.stderr,
        )
        print(
            f"error={type(exc).__name__}: {exc}",
            file=sys.stderr,
        )
        print(
            "result_path="
            + OUTPUT_PATH.as_posix(),
            file=sys.stderr,
        )

        return 2


if __name__ == "__main__":
    sys.exit(main())
