#!/usr/bin/env python3
"""
Stage384 Continuous Trust-State Reverification
& Change Invalidation Gate.

This verifier:
- validates the Stage384 policy and baseline
- recalculates all monitored artifact hashes
- detects missing, changed, or newly inconsistent trust inputs
- classifies changes as material or critical
- invalidates formal-acceptance eligibility for critical changes
- remains in a verified upstream-pending state when unchanged
- does not issue formal acceptance or certificates
"""

from __future__ import annotations

import hashlib
import json
import sys
from pathlib import Path
from typing import Any


STAGE = 384

DEVELOPMENT_POLICY_PATH = Path(
    ".stage384-development-policy.json"
)

POLICY_PATH = Path(
    "development/stage384/"
    "stage384_continuous_verification_policy.json"
)

POLICY_SHA256_PATH = Path(
    "development/stage384/"
    "stage384_continuous_verification_policy.sha256"
)

BASELINE_PATH = Path(
    "development/stage384/"
    "stage384_trust_state_baseline.json"
)

BASELINE_SHA256_PATH = Path(
    "development/stage384/"
    "stage384_trust_state_baseline.sha256"
)

STAGE383_RESULT_PATH = Path(
    "development/stage383/"
    "stage383_formal_acceptance_eligibility_result.json"
)

STAGE383_MANIFEST_PATH = Path(
    "development/stage383/"
    "stage383_recovery_session_manifest.json"
)

OUTPUT_PATH = Path(
    "development/stage384/"
    "stage384_change_detection_result.json"
)


def load_json(path: Path) -> dict[str, Any]:
    data = json.loads(path.read_text(encoding="utf-8"))

    if not isinstance(data, dict):
        raise TypeError(
            f"JSON root must be an object: {path.as_posix()}"
        )

    return data


def sha256_file(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def canonical_json_bytes(value: Any) -> bytes:
    return json.dumps(
        value,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")


def parse_sha256_record(path: Path) -> tuple[str, str]:
    parts = path.read_text(
        encoding="utf-8"
    ).strip().split(maxsplit=1)

    if len(parts) != 2:
        raise ValueError(
            f"invalid SHA-256 record: {path.as_posix()}"
        )

    return parts[0], parts[1]


def add_check(
    checks: list[dict[str, Any]],
    *,
    name: str,
    passed: bool,
    expected: Any,
    actual: Any,
    critical: bool = True,
) -> None:
    checks.append(
        {
            "name": name,
            "critical": critical,
            "passed": bool(passed),
            "expected": expected,
            "actual": actual,
        }
    )


def main() -> int:
    checks: list[dict[str, Any]] = []
    errors: list[str] = []
    detected_changes: list[dict[str, Any]] = []

    try:
        required_control_files = (
            DEVELOPMENT_POLICY_PATH,
            POLICY_PATH,
            POLICY_SHA256_PATH,
            BASELINE_PATH,
            BASELINE_SHA256_PATH,
            STAGE383_RESULT_PATH,
            STAGE383_MANIFEST_PATH,
        )

        for path in required_control_files:
            add_check(
                checks,
                name=(
                    "required_control_file_present:"
                    + path.as_posix()
                ),
                passed=path.is_file(),
                expected=True,
                actual=path.is_file(),
            )

        missing_control_files = [
            path
            for path in required_control_files
            if not path.is_file()
        ]

        if missing_control_files:
            raise FileNotFoundError(
                "missing required control file(s): "
                + ", ".join(
                    path.as_posix()
                    for path in missing_control_files
                )
            )

        development_policy = load_json(
            DEVELOPMENT_POLICY_PATH
        )
        policy = load_json(POLICY_PATH)
        baseline = load_json(BASELINE_PATH)
        stage383_result = load_json(
            STAGE383_RESULT_PATH
        )
        stage383_manifest = load_json(
            STAGE383_MANIFEST_PATH
        )

        recorded_policy_hash, recorded_policy_path = (
            parse_sha256_record(POLICY_SHA256_PATH)
        )
        actual_policy_hash = sha256_file(POLICY_PATH)

        add_check(
            checks,
            name="policy_sha256_valid",
            passed=recorded_policy_hash == actual_policy_hash,
            expected=actual_policy_hash,
            actual=recorded_policy_hash,
        )

        add_check(
            checks,
            name="policy_sha256_record_path_valid",
            passed=recorded_policy_path == POLICY_PATH.as_posix(),
            expected=POLICY_PATH.as_posix(),
            actual=recorded_policy_path,
        )

        recorded_baseline_hash, recorded_baseline_path = (
            parse_sha256_record(BASELINE_SHA256_PATH)
        )
        actual_baseline_file_hash = sha256_file(BASELINE_PATH)

        add_check(
            checks,
            name="baseline_file_sha256_valid",
            passed=(
                recorded_baseline_hash
                == actual_baseline_file_hash
            ),
            expected=actual_baseline_file_hash,
            actual=recorded_baseline_hash,
        )

        add_check(
            checks,
            name="baseline_sha256_record_path_valid",
            passed=(
                recorded_baseline_path
                == BASELINE_PATH.as_posix()
            ),
            expected=BASELINE_PATH.as_posix(),
            actual=recorded_baseline_path,
        )

        embedded_baseline_hash = baseline.get(
            "baseline_sha256"
        )
        baseline_without_hash = dict(baseline)
        baseline_without_hash.pop(
            "baseline_sha256",
            None,
        )

        recalculated_embedded_baseline_hash = (
            hashlib.sha256(
                canonical_json_bytes(
                    baseline_without_hash
                )
            ).hexdigest()
        )

        add_check(
            checks,
            name="embedded_baseline_sha256_valid",
            passed=(
                embedded_baseline_hash
                == recalculated_embedded_baseline_hash
            ),
            expected=recalculated_embedded_baseline_hash,
            actual=embedded_baseline_hash,
        )

        add_check(
            checks,
            name="development_policy_fail_closed",
            passed=(
                development_policy.get(
                    "security_boundary",
                    {},
                ).get("fail_closed")
                is True
            ),
            expected=True,
            actual=development_policy.get(
                "security_boundary",
                {},
            ).get("fail_closed"),
        )

        add_check(
            checks,
            name="development_policy_scope_reduction_forbidden",
            passed=(
                development_policy.get(
                    "security_boundary",
                    {},
                ).get("scope_reduction_allowed")
                is False
            ),
            expected=False,
            actual=development_policy.get(
                "security_boundary",
                {},
            ).get("scope_reduction_allowed"),
        )

        add_check(
            checks,
            name="automatic_formal_acceptance_forbidden",
            passed=(
                policy.get(
                    "preservation_boundary",
                    {},
                ).get(
                    "automatic_formal_acceptance_allowed"
                )
                is False
            ),
            expected=False,
            actual=policy.get(
                "preservation_boundary",
                {},
            ).get(
                "automatic_formal_acceptance_allowed"
            ),
        )

        baseline_artifacts = baseline.get(
            "monitored_artifacts",
            [],
        )

        if not isinstance(baseline_artifacts, list):
            raise TypeError(
                "baseline monitored_artifacts must be a list"
            )

        for record in baseline_artifacts:
            if not isinstance(record, dict):
                raise TypeError(
                    "baseline artifact record must be an object"
                )

            raw_path = record.get("path")
            expected_hash = record.get("sha256")
            expected_size = record.get("size_bytes")
            classification = record.get(
                "change_classification",
                "material",
            )

            if not isinstance(raw_path, str):
                raise TypeError(
                    "artifact path must be a string"
                )

            path = Path(raw_path)

            if not path.is_file():
                detected_changes.append(
                    {
                        "path": raw_path,
                        "change_type": "missing",
                        "classification": "critical",
                        "expected_sha256": expected_hash,
                        "actual_sha256": None,
                        "expected_size_bytes": expected_size,
                        "actual_size_bytes": None,
                    }
                )
                continue

            actual_hash = sha256_file(path)
            actual_size = path.stat().st_size

            if (
                actual_hash != expected_hash
                or actual_size != expected_size
            ):
                detected_changes.append(
                    {
                        "path": raw_path,
                        "change_type": "content_changed",
                        "classification": classification,
                        "expected_sha256": expected_hash,
                        "actual_sha256": actual_hash,
                        "expected_size_bytes": expected_size,
                        "actual_size_bytes": actual_size,
                    }
                )

        current_session_id = (
            stage383_result.get(
                "recovery_session",
                {},
            ).get("session_id")
        )

        baseline_session_id = (
            baseline.get(
                "source_bindings",
                {},
            ).get(
                "stage383_recovery_session_id"
            )
        )

        if current_session_id != baseline_session_id:
            detected_changes.append(
                {
                    "path": STAGE383_RESULT_PATH.as_posix(),
                    "change_type": (
                        "stage383_recovery_session_id_mismatch"
                    ),
                    "classification": "critical",
                    "expected": baseline_session_id,
                    "actual": current_session_id,
                }
            )

        current_manifest_session_id = (
            stage383_manifest.get(
                "recovery_session",
                {},
            ).get("session_id")
        )

        if current_manifest_session_id != baseline_session_id:
            detected_changes.append(
                {
                    "path": STAGE383_MANIFEST_PATH.as_posix(),
                    "change_type": (
                        "stage383_manifest_session_id_mismatch"
                    ),
                    "classification": "critical",
                    "expected": baseline_session_id,
                    "actual": current_manifest_session_id,
                }
            )

        if stage383_result.get(
            "critical_failure_count"
        ) != 0:
            detected_changes.append(
                {
                    "path": STAGE383_RESULT_PATH.as_posix(),
                    "change_type": (
                        "stage383_critical_failure_detected"
                    ),
                    "classification": "critical",
                    "expected": 0,
                    "actual": stage383_result.get(
                        "critical_failure_count"
                    ),
                }
            )

        baseline_eligible = baseline.get(
            "baseline_state",
            {},
        ).get("formal_acceptance_eligible")

        current_eligible = stage383_result.get(
            "formal_acceptance_eligible"
        )

        if (
            baseline_eligible is False
            and current_eligible is True
        ):
            detected_changes.append(
                {
                    "path": STAGE383_RESULT_PATH.as_posix(),
                    "change_type": (
                        "formal_acceptance_eligibility_changed"
                    ),
                    "classification": "material",
                    "expected": False,
                    "actual": True,
                }
            )

        critical_changes = [
            change
            for change in detected_changes
            if change.get("classification") == "critical"
        ]

        material_changes = [
            change
            for change in detected_changes
            if change.get("classification") == "material"
        ]

        critical_failures = sorted(
            check["name"]
            for check in checks
            if (
                check["critical"] is True
                and check["passed"] is False
            )
        )

        if critical_failures:
            decision = "fail_closed"
            verification_status = "invalid"
            reverification_required = True
            eligibility_invalidated = True

        elif critical_changes:
            decision = (
                "formal_acceptance_eligibility_invalidated"
            )
            verification_status = (
                "critical_change_detected"
            )
            reverification_required = True
            eligibility_invalidated = True

        elif material_changes:
            decision = (
                "trust_state_change_reverification_required"
            )
            verification_status = (
                "material_change_detected"
            )
            reverification_required = True
            eligibility_invalidated = False

        elif detected_changes:
            decision = "change_detected_within_policy"
            verification_status = (
                "acceptable_change_detected"
            )
            reverification_required = False
            eligibility_invalidated = False

        else:
            decision = (
                "continuous_trust_state_verified_"
                "upstream_pending"
            )
            verification_status = (
                "verified_unchanged_upstream_pending"
            )
            reverification_required = False
            eligibility_invalidated = False

        result_without_hash: dict[str, Any] = {
            "stage": STAGE,
            "source_stage": 383,
            "engine": (
                "Stage384 Continuous Trust-State "
                "Reverification & Change Invalidation Gate"
            ),
            "execution_mode": "development",
            "development_only": True,
            "verification_mode": (
                "continuous_trust_state_reverification_"
                "and_change_invalidation"
            ),
            "network_access_required": False,
            "fail_closed": True,
            "formal_acceptance_eligible": False,
            "formal_acceptance_issued": False,
            "formal_acceptance": False,
            "pipeline_completed": False,
            "public_release_allowed": False,
            "issuance_transition_allowed": False,
            "policy": {
                "path": POLICY_PATH.as_posix(),
                "sha256": actual_policy_hash,
                "sha256_record_path": (
                    POLICY_SHA256_PATH.as_posix()
                ),
            },
            "baseline": {
                "path": BASELINE_PATH.as_posix(),
                "file_sha256": actual_baseline_file_hash,
                "embedded_baseline_sha256": (
                    embedded_baseline_hash
                ),
                "sha256_record_path": (
                    BASELINE_SHA256_PATH.as_posix()
                ),
                "stage383_recovery_session_id": (
                    baseline_session_id
                ),
            },
            "current_state": {
                "stage383_recovery_session_id": (
                    current_session_id
                ),
                "stage383_decision": (
                    stage383_result.get("decision")
                ),
                "stage383_verification_status": (
                    stage383_result.get(
                        "verification_status"
                    )
                ),
                "stage383_recovery_phase": (
                    stage383_result.get(
                        "recovery_phase"
                    )
                ),
                "stage383_critical_failure_count": (
                    stage383_result.get(
                        "critical_failure_count"
                    )
                ),
                "stage383_formal_acceptance_eligible": (
                    current_eligible
                ),
                "stage383_formal_acceptance_issued": (
                    stage383_result.get(
                        "formal_acceptance_issued"
                    )
                ),
            },
            "change_detected": bool(
                detected_changes
            ),
            "detected_change_count": len(
                detected_changes
            ),
            "material_change_count": len(
                material_changes
            ),
            "critical_change_count": len(
                critical_changes
            ),
            "detected_changes": sorted(
                detected_changes,
                key=lambda item: (
                    str(item.get("path")),
                    str(item.get("change_type")),
                ),
            ),
            "reverification_required": (
                reverification_required
            ),
            "eligibility_invalidated": (
                eligibility_invalidated
            ),
            "decision": decision,
            "verification_status": (
                verification_status
            ),
            "check_count": len(checks),
            "critical_failure_count": len(
                critical_failures
            ),
            "critical_failures": critical_failures,
            "checks": sorted(
                checks,
                key=lambda item: item["name"],
            ),
            "errors": errors,
            "statement": (
                "Stage384 compares the current Stage383 trust "
                "state against a fixed deterministic baseline. "
                "It does not claim uninterrupted real-time "
                "monitoring and does not issue formal acceptance."
            ),
        }

        result_hash = hashlib.sha256(
            canonical_json_bytes(
                result_without_hash
            )
        ).hexdigest()

        result = dict(result_without_hash)
        result["result_sha256"] = result_hash

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

        print("decision=" + decision)
        print(
            "verification_status="
            + verification_status
        )
        print(
            "change_detected="
            + str(bool(detected_changes)).lower()
        )
        print(
            "detected_change_count="
            + str(len(detected_changes))
        )
        print(
            "material_change_count="
            + str(len(material_changes))
        )
        print(
            "critical_change_count="
            + str(len(critical_changes))
        )
        print(
            "reverification_required="
            + str(reverification_required).lower()
        )
        print(
            "eligibility_invalidated="
            + str(eligibility_invalidated).lower()
        )
        print(
            "critical_failure_count="
            + str(len(critical_failures))
        )
        print("result_sha256=" + result_hash)
        print("result_path=" + OUTPUT_PATH.as_posix())

        if critical_failures:
            return 2

        if critical_changes:
            return 1

        if material_changes:
            return 1

        return 0

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

        error_result_without_hash = {
            "stage": STAGE,
            "source_stage": 383,
            "engine": (
                "Stage384 Continuous Trust-State "
                "Reverification & Change Invalidation Gate"
            ),
            "development_only": True,
            "fail_closed": True,
            "formal_acceptance_eligible": False,
            "formal_acceptance_issued": False,
            "formal_acceptance": False,
            "pipeline_completed": False,
            "public_release_allowed": False,
            "issuance_transition_allowed": False,
            "decision": "fail_closed",
            "verification_status": "error",
            "change_detected": True,
            "reverification_required": True,
            "eligibility_invalidated": True,
            "critical_failure_count": 1,
            "critical_failures": [
                "stage384_execution_error"
            ],
            "checks": checks,
            "errors": errors,
        }

        result_hash = hashlib.sha256(
            canonical_json_bytes(
                error_result_without_hash
            )
        ).hexdigest()

        error_result = dict(
            error_result_without_hash
        )
        error_result["result_sha256"] = (
            result_hash
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
