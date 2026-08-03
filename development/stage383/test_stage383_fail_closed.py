#!/usr/bin/env python3
"""Fail-Closed tests for Stage383."""

from __future__ import annotations

import contextlib
import hashlib
import importlib.util
import io
import json
import shutil
import tempfile
import unittest
from pathlib import Path
from typing import Any


REPOSITORY_ROOT = Path(__file__).resolve().parents[2]

VERIFIER_SOURCE = (
    REPOSITORY_ROOT
    / "development/stage383/"
    / "verify_stage383_recovery_chain.py"
)


def canonical_json_bytes(value: Any) -> bytes:
    return json.dumps(
        value,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")


def sha256_file(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def load_json(path: Path) -> dict[str, Any]:
    data = json.loads(path.read_text(encoding="utf-8"))

    if not isinstance(data, dict):
        raise TypeError(f"JSON root is not an object: {path}")

    return data


def write_json(path: Path, data: dict[str, Any]) -> None:
    path.write_text(
        json.dumps(
            data,
            ensure_ascii=False,
            indent=2,
            sort_keys=True,
        )
        + "\n",
        encoding="utf-8",
        newline="\n",
    )


def rebuild_embedded_hash(
    path: Path,
    field_name: str,
) -> None:
    data = load_json(path)
    payload = dict(data)
    payload.pop(field_name, None)

    data[field_name] = hashlib.sha256(
        canonical_json_bytes(payload)
    ).hexdigest()

    write_json(path, data)


def load_verifier_module():
    spec = importlib.util.spec_from_file_location(
        "stage383_verifier_under_test",
        VERIFIER_SOURCE,
    )

    if spec is None or spec.loader is None:
        raise RuntimeError("Unable to load Stage383 verifier")

    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)

    return module


class Stage383FailClosedTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary_directory = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary_directory.name)

        relative_files = (
            ".stage383-development-policy.json",
            "development/stage383/"
            "stage383_recovery_orchestration_contract.json",
            "development/stage383/"
            "stage383_recovery_orchestration_contract.sha256",
            "docs/timestamp-finalization/"
            "stage377_dual_timestamp_finalization_result.json",
            "docs/qkd/"
            "stage378_qkd_safety_metadata_binding_result.json",
            "development/stage379/"
            "stage379_scoped_total_verification_result.json",
            "development/stage380/"
            "stage380_independent_verification_result.json",
            "docs/verification/stage381/"
            "stage381_cross_platform_verification_package_result.json",
            "development/stage382/policy-profiles/"
            "qsp-dual-timestamp-final-acceptance-v1.json",
            "development/stage382/policy-profiles/"
            "qsp-dual-timestamp-final-acceptance-v1.sha256",
            "development/stage382/"
            "stage382_upstream_finalization_result.json",
            "development/stage382/"
            "stage382_policy_activation_manifest.json",
        )

        for relative_name in relative_files:
            source = REPOSITORY_ROOT / relative_name
            destination = self.root / relative_name

            destination.parent.mkdir(
                parents=True,
                exist_ok=True,
            )

            shutil.copy2(source, destination)

        self.module = load_verifier_module()
        self.patch_module_paths()

        # The verifier paths now point to this test's temporary
        # directory. Rebuild the copied SHA-256 records so their
        # recorded paths and hashes refer to the temporary fixture,
        # not to the source repository.
        self.rebuild_contract_record()
        self.rebuild_stage382_policy_record()

    def tearDown(self) -> None:
        self.temporary_directory.cleanup()

    def patch_module_paths(self) -> None:
        path_mapping = {
            "DEVELOPMENT_POLICY_PATH":
                ".stage383-development-policy.json",

            "CONTRACT_PATH":
                "development/stage383/"
                "stage383_recovery_orchestration_contract.json",

            "CONTRACT_SHA256_PATH":
                "development/stage383/"
                "stage383_recovery_orchestration_contract.sha256",

            "STAGE377_RESULT_PATH":
                "docs/timestamp-finalization/"
                "stage377_dual_timestamp_finalization_result.json",

            "STAGE378_RESULT_PATH":
                "docs/qkd/"
                "stage378_qkd_safety_metadata_binding_result.json",

            "STAGE379_RESULT_PATH":
                "development/stage379/"
                "stage379_scoped_total_verification_result.json",

            "STAGE380_RESULT_PATH":
                "development/stage380/"
                "stage380_independent_verification_result.json",

            "STAGE381_RESULT_PATH":
                "docs/verification/stage381/"
                "stage381_cross_platform_verification_package_result.json",

            "STAGE382_POLICY_PATH":
                "development/stage382/policy-profiles/"
                "qsp-dual-timestamp-final-acceptance-v1.json",

            "STAGE382_POLICY_SHA256_PATH":
                "development/stage382/policy-profiles/"
                "qsp-dual-timestamp-final-acceptance-v1.sha256",

            "STAGE382_RESULT_PATH":
                "development/stage382/"
                "stage382_upstream_finalization_result.json",

            "STAGE382_MANIFEST_PATH":
                "development/stage382/"
                "stage382_policy_activation_manifest.json",

            "OUTPUT_PATH":
                "development/stage383/"
                "stage383_formal_acceptance_eligibility_result.json",
        }

        for attribute_name, relative_name in path_mapping.items():
            setattr(
                self.module,
                attribute_name,
                self.root / relative_name,
            )

    def path(self, relative_name: str) -> Path:
        return self.root / relative_name

    def run_verifier(
        self,
    ) -> tuple[int, dict[str, Any]]:
        standard_output = io.StringIO()
        standard_error = io.StringIO()

        with (
            contextlib.redirect_stdout(standard_output),
            contextlib.redirect_stderr(standard_error),
        ):
            exit_code = self.module.main()

        output_path = self.module.OUTPUT_PATH

        self.assertTrue(
            output_path.is_file(),
            msg=(
                "Stage383 verifier did not create a result. "
                f"stdout={standard_output.getvalue()!r}, "
                f"stderr={standard_error.getvalue()!r}"
            ),
        )

        return exit_code, load_json(output_path)

    def rebuild_contract_record(self) -> None:
        contract = self.module.CONTRACT_PATH
        record = self.module.CONTRACT_SHA256_PATH

        record.write_text(
            f"{sha256_file(contract)}  {contract.as_posix()}\n",
            encoding="utf-8",
            newline="\n",
        )

    def rebuild_stage382_policy_record(self) -> None:
        policy = self.module.STAGE382_POLICY_PATH
        record = self.module.STAGE382_POLICY_SHA256_PATH

        record.write_text(
            f"{sha256_file(policy)}  {policy.as_posix()}\n",
            encoding="utf-8",
            newline="\n",
        )

    def rebuild_stage382_manifest_hash(self) -> None:
        rebuild_embedded_hash(
            self.module.STAGE382_MANIFEST_PATH,
            "manifest_sha256",
        )

    def bind_stage377_file_to_manifest(self) -> None:
        manifest = load_json(
            self.module.STAGE382_MANIFEST_PATH
        )

        binding = manifest[
            "upstream_bindings"
        ]["stage377"]

        binding["file_sha256"] = sha256_file(
            self.module.STAGE377_RESULT_PATH
        )

        stage377 = load_json(
            self.module.STAGE377_RESULT_PATH
        )

        binding["embedded_result_sha256"] = (
            stage377.get("result_sha256")
        )

        write_json(
            self.module.STAGE382_MANIFEST_PATH,
            manifest,
        )

        self.rebuild_stage382_manifest_hash()

    def test_current_pending_state_is_valid(self) -> None:
        exit_code, result = self.run_verifier()

        self.assertEqual(exit_code, 0)
        self.assertEqual(
            result.get("decision"),
            "upstream_finalization_pending",
        )
        self.assertEqual(
            result.get("verification_status"),
            "verified_pending_upstream",
        )
        self.assertEqual(
            result.get("recovery_phase"),
            "waiting_for_stage377",
        )
        self.assertEqual(
            result.get("critical_failure_count"),
            0,
        )
        self.assertFalse(
            result.get("formal_acceptance_eligible")
        )
        self.assertFalse(
            result.get("formal_acceptance_issued")
        )
        self.assertFalse(
            result.get("formal_acceptance")
        )
        self.assertFalse(
            result.get("pipeline_completed")
        )

    def test_missing_required_file_fails_closed(self) -> None:
        self.module.STAGE378_RESULT_PATH.unlink()

        exit_code, result = self.run_verifier()

        self.assertEqual(exit_code, 2)
        self.assertEqual(
            result.get("decision"),
            "fail_closed",
        )
        self.assertEqual(
            result.get("verification_status"),
            "error",
        )
        self.assertFalse(
            result.get("formal_acceptance_eligible")
        )

    def test_contract_tampering_fails_closed(self) -> None:
        contract = load_json(
            self.module.CONTRACT_PATH
        )

        contract["scope_reduction_allowed"] = True

        write_json(
            self.module.CONTRACT_PATH,
            contract,
        )

        exit_code, result = self.run_verifier()

        self.assertEqual(exit_code, 2)
        self.assertEqual(
            result.get("decision"),
            "fail_closed",
        )
        self.assertIn(
            "contract_sha256_valid",
            result.get("critical_failures", []),
        )

    def test_manifest_tampering_fails_closed(self) -> None:
        manifest = load_json(
            self.module.STAGE382_MANIFEST_PATH
        )

        manifest["preservation_statement"] = (
            "tampered preservation statement"
        )

        write_json(
            self.module.STAGE382_MANIFEST_PATH,
            manifest,
        )

        exit_code, result = self.run_verifier()

        self.assertEqual(exit_code, 2)
        self.assertEqual(
            result.get("decision"),
            "fail_closed",
        )
        self.assertIn(
            "stage382_manifest_embedded_sha256_valid",
            result.get("critical_failures", []),
        )

    def test_mixed_stage377_artifact_fails_closed(self) -> None:
        stage377 = load_json(
            self.module.STAGE377_RESULT_PATH
        )

        stage377["verified_proof_count"] = 99

        write_json(
            self.module.STAGE377_RESULT_PATH,
            stage377,
        )

        exit_code, result = self.run_verifier()

        self.assertEqual(exit_code, 2)
        self.assertEqual(
            result.get("decision"),
            "fail_closed",
        )
        self.assertIn(
            "stage377_manifest_file_sha256_matches",
            result.get("critical_failures", []),
        )

    def test_qkd_publication_boundary_failure(
        self,
    ) -> None:
        stage378 = load_json(
            self.module.STAGE378_RESULT_PATH
        )

        stage378[
            "raw_qkd_key_publication_detected"
        ] = True

        write_json(
            self.module.STAGE378_RESULT_PATH,
            stage378,
        )

        manifest = load_json(
            self.module.STAGE382_MANIFEST_PATH
        )

        binding = manifest[
            "upstream_bindings"
        ]["stage378"]

        binding["file_sha256"] = sha256_file(
            self.module.STAGE378_RESULT_PATH
        )
        binding["raw_qkd_key_publication_detected"] = True

        write_json(
            self.module.STAGE382_MANIFEST_PATH,
            manifest,
        )
        self.rebuild_stage382_manifest_hash()

        exit_code, result = self.run_verifier()

        self.assertEqual(exit_code, 2)
        self.assertEqual(
            result.get("decision"),
            "fail_closed",
        )
        self.assertIn(
            "stage378_raw_qkd_key_not_published",
            result.get("critical_failures", []),
        )

    def test_automatic_issuance_policy_fails_closed(
        self,
    ) -> None:
        policy = load_json(
            self.module.DEVELOPMENT_POLICY_PATH
        )

        policy["requirements"][
            "automatic_formal_acceptance_issuance_allowed"
        ] = True

        write_json(
            self.module.DEVELOPMENT_POLICY_PATH,
            policy,
        )

        exit_code, result = self.run_verifier()

        self.assertEqual(exit_code, 2)
        self.assertEqual(
            result.get("decision"),
            "fail_closed",
        )
        self.assertIn(
            "automatic_formal_acceptance_issuance_forbidden",
            result.get("critical_failures", []),
        )

    def test_completed_stage377_requires_downstream_reverification(
        self,
    ) -> None:
        stage377 = load_json(
            self.module.STAGE377_RESULT_PATH
        )

        stage377.update(
            {
                "decision":
                    "dual_timestamp_final_acceptance_verified",
                "verified_proof_count": 2,
                "effective_final_acceptance": True,
                "timestamp_verified": True,
                "rfc3161_verified": True,
                "opentimestamps_verified": True,
            }
        )

        write_json(
            self.module.STAGE377_RESULT_PATH,
            stage377,
        )

        self.bind_stage377_file_to_manifest()

        exit_code, result = self.run_verifier()

        self.assertEqual(exit_code, 1)
        self.assertEqual(
            result.get("decision"),
            "fail_closed",
        )
        self.assertEqual(
            result.get("verification_status"),
            "verified_not_eligible",
        )
        self.assertEqual(
            result.get("recovery_phase"),
            "downstream_reverification_required",
        )
        self.assertTrue(
            result.get(
                "upstream_state",
                {},
            ).get("stage377_complete")
        )
        self.assertFalse(
            result.get("formal_acceptance_eligible")
        )
        self.assertFalse(
            result.get("formal_acceptance_issued")
        )

    def test_recovery_session_id_is_deterministic(
        self,
    ) -> None:
        first_exit_code, first_result = (
            self.run_verifier()
        )

        second_exit_code, second_result = (
            self.run_verifier()
        )

        self.assertEqual(first_exit_code, 0)
        self.assertEqual(second_exit_code, 0)

        first_session = first_result.get(
            "recovery_session",
            {},
        ).get("session_id")

        second_session = second_result.get(
            "recovery_session",
            {},
        ).get("session_id")

        self.assertEqual(
            first_session,
            second_session,
        )

        self.assertTrue(
            first_result.get(
                "recovery_session",
                {},
            ).get("deterministic")
        )

    def test_stage383_never_issues_formal_acceptance(
        self,
    ) -> None:
        _, result = self.run_verifier()

        self.assertFalse(
            result.get("formal_acceptance_issued")
        )
        self.assertFalse(
            result.get("formal_acceptance")
        )
        self.assertFalse(
            result.get("pipeline_completed")
        )
        self.assertTrue(
            result.get(
                "manual_or_verified_issuance_transition_required"
            )
        )


if __name__ == "__main__":
    unittest.main(verbosity=2)
