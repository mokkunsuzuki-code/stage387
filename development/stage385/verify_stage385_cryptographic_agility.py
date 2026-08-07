#!/usr/bin/env python3

from __future__ import annotations

import hashlib
import json
import sys
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parents[2]

STAGE = 385

POLICY_PATH = (
    ROOT
    / "development/stage385/"
    / "stage385_cryptographic_agility_policy.json"
)

POLICY_SHA256_PATH = (
    ROOT
    / "development/stage385/"
    / "stage385_cryptographic_agility_policy.sha256"
)

INVENTORY_PATH = (
    ROOT
    / "development/stage385/"
    / "stage385_cryptographic_inventory.json"
)

INVENTORY_SHA256_PATH = (
    ROOT
    / "development/stage385/"
    / "stage385_cryptographic_inventory.sha256"
)

STAGE384_RESULT_PATH = (
    ROOT
    / "development/stage384/"
    / "stage384_change_detection_result.json"
)

STAGE384_RESULT_SHA256_PATH = (
    ROOT
    / "development/stage384/"
    / "stage384_change_detection_result.sha256"
)

STAGE384_MANIFEST_PATH = (
    ROOT
    / "development/stage384/"
    / "stage384_continuous_verification_manifest.json"
)

STAGE384_MANIFEST_SHA256_PATH = (
    ROOT
    / "development/stage384/"
    / "stage384_continuous_verification_manifest.sha256"
)

OUTPUT_PATH = (
    ROOT
    / "development/stage385/"
    / "stage385_pqc_migration_readiness_result.json"
)


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


def load_json(path: Path) -> Any:
    return json.loads(
        path.read_text(encoding="utf-8")
    )


def relative(path: Path) -> str:
    return path.relative_to(ROOT).as_posix()


def read_sha256_record(
    record_path: Path,
    expected_target: Path,
) -> tuple[str, str]:
    text = record_path.read_text(
        encoding="utf-8"
    ).strip()

    parts = text.split(maxsplit=1)

    if len(parts) != 2:
        raise ValueError(
            "invalid SHA-256 record format: "
            + relative(record_path)
        )

    recorded_hash, recorded_target = parts

    return recorded_hash, recorded_target


def embedded_hash_valid(
    data: dict[str, Any],
    field: str,
) -> bool:
    embedded = data.get(field)

    if not isinstance(embedded, str):
        return False

    copied = dict(data)
    copied.pop(field, None)

    recalculated = sha256_bytes(
        canonical_json_bytes(copied)
    )

    return embedded == recalculated


def add_check(
    checks: list[dict[str, Any]],
    name: str,
    passed: bool,
    critical: bool = False,
    detail: str | None = None,
) -> None:
    item: dict[str, Any] = {
        "name": name,
        "passed": bool(passed),
        "critical": bool(critical),
    }

    if detail is not None:
        item["detail"] = detail

    checks.append(item)


def main() -> int:
    checks: list[dict[str, Any]] = []
    errors: list[str] = []

    required_files = [
        POLICY_PATH,
        POLICY_SHA256_PATH,
        INVENTORY_PATH,
        INVENTORY_SHA256_PATH,
        STAGE384_RESULT_PATH,
        STAGE384_RESULT_SHA256_PATH,
        STAGE384_MANIFEST_PATH,
        STAGE384_MANIFEST_SHA256_PATH,
    ]

    for path in required_files:
        exists = path.is_file()

        add_check(
            checks,
            "required_file_present:"
            + relative(path),
            exists,
            critical=True,
        )

        if not exists:
            errors.append(
                "required file missing: "
                + relative(path)
            )

    if errors:
        result = {
            "stage": STAGE,
            "source_stage": 384,
            "engine":
                "Stage385 Cryptographic Agility "
                "Inventory, PQC Migration Readiness "
                "& Algorithm Policy Enforcement Gate",
            "verification_mode":
                "cryptographic_agility_inventory_"
                "pqc_migration_readiness_and_"
                "algorithm_policy_enforcement",
            "development_only": True,
            "decision": "fail_closed",
            "verification_status":
                "integrity_failure",
            "fail_closed": True,
            "formal_acceptance": False,
            "formal_acceptance_eligible": False,
            "formal_acceptance_issued": False,
            "pipeline_completed": False,
            "public_release_allowed": False,
            "critical_failure_count": len(errors),
            "critical_failures": errors,
            "checks": checks,
            "errors": errors,
        }

        result["result_sha256"] = sha256_bytes(
            canonical_json_bytes(result)
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

        print("decision=fail_closed")
        print(
            "critical_failure_count="
            + str(len(errors))
        )
        print(
            "result_path="
            + relative(OUTPUT_PATH)
        )

        return 1

    try:
        policy = load_json(POLICY_PATH)
        inventory = load_json(INVENTORY_PATH)
        stage384_result = load_json(
            STAGE384_RESULT_PATH
        )
        stage384_manifest = load_json(
            STAGE384_MANIFEST_PATH
        )
    except Exception as exc:
        errors.append(
            "JSON load failure: "
            + str(exc)
        )

        policy = {}
        inventory = {}
        stage384_result = {}
        stage384_manifest = {}

    add_check(
        checks,
        "json_inputs_loaded",
        not errors,
        critical=True,
    )

    #
    # SHA-256 record verification
    #

    hash_targets = [
        (
            "policy",
            POLICY_PATH,
            POLICY_SHA256_PATH,
        ),
        (
            "inventory",
            INVENTORY_PATH,
            INVENTORY_SHA256_PATH,
        ),
        (
            "stage384_result",
            STAGE384_RESULT_PATH,
            STAGE384_RESULT_SHA256_PATH,
        ),
        (
            "stage384_manifest",
            STAGE384_MANIFEST_PATH,
            STAGE384_MANIFEST_SHA256_PATH,
        ),
    ]

    resolved_hashes: dict[str, str] = {}

    for (
        name,
        target,
        record,
    ) in hash_targets:
        try:
            (
                recorded_hash,
                recorded_target,
            ) = read_sha256_record(
                record,
                target,
            )

            actual_hash = sha256_file(target)

            expected_path = relative(target)

            hash_valid = (
                recorded_hash == actual_hash
            )

            path_valid = (
                recorded_target == expected_path
            )

            resolved_hashes[name] = (
                actual_hash
            )

            add_check(
                checks,
                name + "_sha256_valid",
                hash_valid,
                critical=True,
            )

            add_check(
                checks,
                name
                + "_sha256_record_path_valid",
                path_valid,
                critical=True,
            )

            if not hash_valid:
                errors.append(
                    name
                    + " SHA-256 mismatch"
                )

            if not path_valid:
                errors.append(
                    name
                    + " SHA-256 path mismatch"
                )

        except Exception as exc:
            add_check(
                checks,
                name + "_sha256_valid",
                False,
                critical=True,
                detail=str(exc),
            )

            errors.append(
                name
                + " SHA-256 verification failure: "
                + str(exc)
            )

    #
    # Basic stage and policy integrity
    #

    policy_stage_valid = (
        policy.get("stage") == 385
        and policy.get("source_stage") == 384
    )

    add_check(
        checks,
        "policy_stage_valid",
        policy_stage_valid,
        critical=True,
    )

    if not policy_stage_valid:
        errors.append(
            "Stage385 policy stage/source_stage invalid"
        )

    inventory_stage_valid = (
        inventory.get("stage") == 385
        and inventory.get("source_stage") == 384
    )

    add_check(
        checks,
        "inventory_stage_valid",
        inventory_stage_valid,
        critical=True,
    )

    if not inventory_stage_valid:
        errors.append(
            "Stage385 inventory stage/source_stage invalid"
        )

    #
    # Security/publication boundary
    #

    publication_boundary = inventory.get(
        "publication_boundary",
        {},
    )

    prohibited_publication_fields = (
        "private_key_material_included",
        "key_seed_material_included",
        "credential_material_included",
        "token_material_included",
        "raw_qkd_secret_material_included",
        "raw_timestamp_binary_included",
    )

    for field in prohibited_publication_fields:
        safe = (
            publication_boundary.get(field)
            is False
        )

        add_check(
            checks,
            "publication_boundary_safe:"
            + field,
            safe,
            critical=True,
        )

        if not safe:
            errors.append(
                "publication boundary violation: "
                + field
            )

    public_metadata_only = (
        publication_boundary.get(
            "public_metadata_only"
        )
        is True
    )

    add_check(
        checks,
        "public_metadata_only",
        public_metadata_only,
        critical=True,
    )

    if not public_metadata_only:
        errors.append(
            "Stage385 inventory is not "
            "metadata-only"
        )

    #
    # Stage384 gate
    #

    stage384_gate = policy.get(
        "stage384_gate",
        {},
    )

    stage384_conditions = {
        "decision": (
            stage384_result.get("decision")
            == stage384_gate.get(
                "required_decision"
            )
        ),
        "verification_status": (
            stage384_result.get(
                "verification_status"
            )
            == stage384_gate.get(
                "required_verification_status"
            )
        ),
        "change_detected": (
            stage384_result.get(
                "change_detected"
            )
            is stage384_gate.get(
                "change_detected_required"
            )
        ),
        "reverification_required": (
            stage384_result.get(
                "reverification_required"
            )
            is stage384_gate.get(
                "reverification_required_required"
            )
        ),
        "eligibility_invalidated": (
            stage384_result.get(
                "eligibility_invalidated"
            )
            is stage384_gate.get(
                "eligibility_invalidated_required"
            )
        ),
        "critical_failure_count": (
            stage384_result.get(
                "critical_failure_count"
            )
            == stage384_gate.get(
                "critical_failure_count_required"
            )
        ),
    }

    for name, passed in (
        stage384_conditions.items()
    ):
        add_check(
            checks,
            "stage384_gate:" + name,
            passed,
            critical=True,
        )

    stage384_gate_valid = all(
        stage384_conditions.values()
    )

    if not stage384_gate_valid:
        errors.append(
            "Stage384 trust state changed "
            "or requires reverification"
        )

    #
    # Embedded Stage384 hashes
    #

    stage384_result_embedded_valid = (
        embedded_hash_valid(
            stage384_result,
            "result_sha256",
        )
    )

    add_check(
        checks,
        "stage384_embedded_result_sha256_valid",
        stage384_result_embedded_valid,
        critical=True,
    )

    if not stage384_result_embedded_valid:
        errors.append(
            "Stage384 embedded result SHA-256 invalid"
        )

    stage384_manifest_embedded_valid = (
        embedded_hash_valid(
            stage384_manifest,
            "manifest_sha256",
        )
    )

    add_check(
        checks,
        "stage384_embedded_manifest_sha256_valid",
        stage384_manifest_embedded_valid,
        critical=True,
    )

    if not stage384_manifest_embedded_valid:
        errors.append(
            "Stage384 embedded manifest SHA-256 invalid"
        )

    #
    # Inventory structure
    #

    assets = inventory.get(
        "assets",
        [],
    )

    if not isinstance(assets, list):
        assets = []
        errors.append(
            "inventory assets must be a list"
        )

    asset_ids = [
        item.get("asset_id")
        for item in assets
        if isinstance(item, dict)
    ]

    duplicate_asset_ids = sorted({
        asset_id
        for asset_id in asset_ids
        if asset_ids.count(asset_id) > 1
    })

    no_duplicate_ids = (
        len(duplicate_asset_ids) == 0
    )

    add_check(
        checks,
        "unique_asset_ids",
        no_duplicate_ids,
        critical=True,
    )

    if not no_duplicate_ids:
        errors.append(
            "duplicate asset_id: "
            + ", ".join(
                str(value)
                for value in duplicate_asset_ids
            )
        )

    required_asset_fields = (
        "asset_id",
        "asset_type",
        "purpose",
        "algorithm_family",
        "algorithm_identifier",
        "algorithm_status",
        "migration_state",
        "inventory_confidence",
        "verification_evidence",
    )

    missing_required_fields: list[str] = []

    for asset in assets:
        if not isinstance(asset, dict):
            missing_required_fields.append(
                "<non-dict asset>"
            )
            continue

        missing = [
            field
            for field in required_asset_fields
            if field not in asset
        ]

        if missing:
            missing_required_fields.append(
                str(asset.get("asset_id"))
                + ":"
                + ",".join(missing)
            )

    required_fields_valid = (
        not missing_required_fields
    )

    add_check(
        checks,
        "required_asset_fields_valid",
        required_fields_valid,
        critical=True,
    )

    if not required_fields_valid:
        errors.append(
            "missing required asset fields: "
            + "; ".join(
                missing_required_fields
            )
        )

    #
    # Evidence references
    #

    missing_evidence_paths: list[str] = []

    for asset in assets:
        if not isinstance(asset, dict):
            continue

        asset_id = str(
            asset.get("asset_id")
        )

        evidence = asset.get(
            "verification_evidence",
            [],
        )

        if (
            asset.get(
                "inventory_confidence"
            )
            in {
                "verified_metadata",
                "verified_execution_evidence",
            }
            and not evidence
        ):
            errors.append(
                "verified claim without evidence: "
                + asset_id
            )

        if not isinstance(evidence, list):
            errors.append(
                "verification_evidence is not list: "
                + asset_id
            )
            continue

        for evidence_path in evidence:
            if not isinstance(
                evidence_path,
                str,
            ):
                missing_evidence_paths.append(
                    asset_id
                    + ":<invalid path>"
                )
                continue

            evidence_file = (
                ROOT / evidence_path
            )

            if not evidence_file.is_file():
                missing_evidence_paths.append(
                    asset_id
                    + ":"
                    + evidence_path
                )

    evidence_paths_valid = (
        not missing_evidence_paths
    )

    add_check(
        checks,
        "verification_evidence_paths_exist",
        evidence_paths_valid,
        critical=True,
    )

    if not evidence_paths_valid:
        errors.append(
            "missing verification evidence: "
            + "; ".join(
                missing_evidence_paths
            )
        )

    #
    # Inventory classification
    #

    prohibited_assets: list[str] = []
    migration_required_assets: list[str] = []
    incomplete_assets: list[str] = []

    for asset in assets:
        if not isinstance(asset, dict):
            continue

        asset_id = str(
            asset.get("asset_id")
        )

        status = asset.get(
            "algorithm_status"
        )

        identifier = asset.get(
            "algorithm_identifier"
        )

        if status == "prohibited":
            prohibited_assets.append(
                asset_id
            )

        if status == "migration_required":
            migration_required_assets.append(
                asset_id
            )

        if (
            status in {
                "evidence_required",
                "unknown",
            }
            or identifier == "unknown"
        ):
            incomplete_assets.append(
                asset_id
            )

    prohibited_assets = sorted(
        set(prohibited_assets)
    )

    migration_required_assets = sorted(
        set(migration_required_assets)
    )

    incomplete_assets = sorted(
        set(incomplete_assets)
    )

    #
    # Special migration observations
    #

    observation = inventory.get(
        "current_migration_observation",
        {},
    )

    classical_signature_present = (
        observation.get(
            "classical_public_key_signature_present"
        )
        is True
    )

    pqc_signature_verified = (
        observation.get(
            "pqc_signature_execution_verified"
        )
        is True
    )

    hybrid_evidence_present = (
        observation.get(
            "hybrid_execution_evidence_present"
        )
        is True
    )

    public_mldsa_key_available = (
        observation.get(
            "current_public_mldsa_key_available"
        )
        is True
    )

    entire_system_quantum_safe = (
        observation.get(
            "entire_system_quantum_safe"
        )
        is True
    )

    add_check(
        checks,
        "pqc_signature_execution_verified",
        pqc_signature_verified,
        critical=False,
    )

    add_check(
        checks,
        "hybrid_execution_evidence_present",
        hybrid_evidence_present,
        critical=False,
    )

    add_check(
        checks,
        "entire_system_quantum_safe_not_claimed",
        not entire_system_quantum_safe,
        critical=True,
    )

    if entire_system_quantum_safe:
        errors.append(
            "unsupported entire-system "
            "quantum-safe claim detected"
        )

    #
    # Determine result with fixed precedence
    #

    critical_failures = list(
        dict.fromkeys(errors)
    )

    critical_failure_count = len(
        critical_failures
    )

    if critical_failure_count > 0:
        if not stage384_gate_valid:
            decision = (
                "stage384_change_requires_reverification"
            )
            verification_status = (
                "upstream_reverification_required"
            )
        else:
            decision = "fail_closed"
            verification_status = (
                "integrity_failure"
            )

    elif prohibited_assets:
        decision = (
            "prohibited_algorithm_detected"
        )
        verification_status = (
            "verified_prohibited_algorithm_detected"
        )

    elif incomplete_assets:
        decision = (
            "cryptographic_inventory_incomplete"
        )
        verification_status = (
            "verified_with_inventory_gaps_"
            "upstream_pending"
        )

    elif migration_required_assets:
        decision = "pqc_migration_required"
        verification_status = (
            "verified_migration_required_"
            "upstream_pending"
        )

    else:
        decision = (
            "cryptographic_agility_profile_verified"
        )
        verification_status = (
            "verified_cryptographic_agility_"
            "upstream_pending"
        )

    #
    # Formal acceptance remains false.
    #

    result: dict[str, Any] = {
        "stage": STAGE,
        "source_stage": 384,
        "engine":
            "Stage385 Cryptographic Agility "
            "Inventory, PQC Migration Readiness "
            "& Algorithm Policy Enforcement Gate",

        "verification_mode":
            "cryptographic_agility_inventory_"
            "pqc_migration_readiness_and_"
            "algorithm_policy_enforcement",

        "development_only": True,
        "fail_closed": True,

        "decision": decision,
        "verification_status":
            verification_status,

        "formal_acceptance": False,
        "formal_acceptance_eligible": False,
        "formal_acceptance_issued": False,
        "pipeline_completed": False,
        "public_release_allowed": False,

        "policy_binding": {
            "path": relative(
                POLICY_PATH
            ),
            "file_sha256":
                resolved_hashes.get(
                    "policy"
                ),
        },

        "inventory_binding": {
            "path": relative(
                INVENTORY_PATH
            ),
            "file_sha256":
                resolved_hashes.get(
                    "inventory"
                ),
            "asset_count": len(assets),
        },

        "stage384_binding": {
            "result_path":
                relative(
                    STAGE384_RESULT_PATH
                ),
            "result_file_sha256":
                resolved_hashes.get(
                    "stage384_result"
                ),
            "manifest_path":
                relative(
                    STAGE384_MANIFEST_PATH
                ),
            "manifest_file_sha256":
                resolved_hashes.get(
                    "stage384_manifest"
                ),
            "decision":
                stage384_result.get(
                    "decision"
                ),
            "verification_status":
                stage384_result.get(
                    "verification_status"
                ),
            "change_detected":
                stage384_result.get(
                    "change_detected"
                ),
            "reverification_required":
                stage384_result.get(
                    "reverification_required"
                ),
            "eligibility_invalidated":
                stage384_result.get(
                    "eligibility_invalidated"
                ),
            "critical_failure_count":
                stage384_result.get(
                    "critical_failure_count"
                ),
        },

        "cryptographic_state": {
            "asset_count": len(assets),

            "prohibited_algorithm_count":
                len(prohibited_assets),

            "prohibited_assets":
                prohibited_assets,

            "migration_required_count":
                len(
                    migration_required_assets
                ),

            "migration_required_assets":
                migration_required_assets,

            "inventory_incomplete_count":
                len(incomplete_assets),

            "inventory_incomplete_assets":
                incomplete_assets,

            "classical_public_key_signature_present":
                classical_signature_present,

            "pqc_signature_execution_verified":
                pqc_signature_verified,

            "hybrid_execution_evidence_present":
                hybrid_evidence_present,

            "current_public_mldsa_key_available":
                public_mldsa_key_available,

            "entire_system_quantum_safe":
                False,
        },

        "migration_readiness": {
            "pqc_component_verified":
                pqc_signature_verified,

            "classical_signature_migration_required":
                bool(
                    migration_required_assets
                ),

            "inventory_completion_required":
                bool(
                    incomplete_assets
                ),

            "standalone_public_mldsa_reverification_available":
                public_mldsa_key_available,

            "ready_for_pqc_only_claim":
                False,

            "ready_for_entire_system_quantum_safe_claim":
                False,
        },

        "check_count": len(checks),
        "checks": checks,

        "critical_failure_count":
            critical_failure_count,

        "critical_failures":
            critical_failures,

        "errors":
            critical_failures,

        "statement": (
            "Stage385 inventories public cryptographic "
            "metadata and verified evidence without "
            "publishing private key material. "
            "It does not claim the entire system is "
            "quantum-safe and does not upgrade upstream "
            "formal acceptance."
        ),
    }

    result["result_sha256"] = sha256_bytes(
        canonical_json_bytes(result)
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

    print(
        "decision="
        + str(result["decision"])
    )

    print(
        "verification_status="
        + str(
            result["verification_status"]
        )
    )

    print(
        "asset_count="
        + str(len(assets))
    )

    print(
        "migration_required_count="
        + str(
            len(
                migration_required_assets
            )
        )
    )

    print(
        "inventory_incomplete_count="
        + str(
            len(incomplete_assets)
        )
    )

    print(
        "prohibited_algorithm_count="
        + str(
            len(prohibited_assets)
        )
    )

    print(
        "pqc_signature_execution_verified="
        + str(
            pqc_signature_verified
        ).lower()
    )

    print(
        "current_public_mldsa_key_available="
        + str(
            public_mldsa_key_available
        ).lower()
    )

    print(
        "critical_failure_count="
        + str(
            critical_failure_count
        )
    )

    print(
        "result_sha256="
        + result["result_sha256"]
    )

    print(
        "result_path="
        + relative(OUTPUT_PATH)
    )

    if critical_failure_count > 0:
        return 1

    return 0


if __name__ == "__main__":
    sys.exit(main())
