#!/usr/bin/env python3
"""
Fail-Closed tests for Stage384.

All destructive test changes are performed inside temporary repository
copies. The real Stage377 through Stage384 files are not modified.
"""

from __future__ import annotations

import json
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from typing import Any


REPOSITORY_ROOT = Path(__file__).resolve().parents[2]

VERIFIER_RELATIVE_PATH = Path(
    "development/stage384/"
    "verify_stage384_continuous_trust_state.py"
)

RESULT_RELATIVE_PATH = Path(
    "development/stage384/"
    "stage384_change_detection_result.json"
)

POLICY_RELATIVE_PATH = Path(
    "development/stage384/"
    "stage384_continuous_verification_policy.json"
)

POLICY_SHA256_RELATIVE_PATH = Path(
    "development/stage384/"
    "stage384_continuous_verification_policy.sha256"
)

BASELINE_RELATIVE_PATH = Path(
    "development/stage384/"
    "stage384_trust_state_baseline.json"
)

BASELINE_SHA256_RELATIVE_PATH = Path(
    "development/stage384/"
    "stage384_trust_state_baseline.sha256"
)

STAGE383_RESULT_RELATIVE_PATH = Path(
    "development/stage383/"
    "stage383_formal_acceptance_eligibility_result.json"
)

STAGE383_MANIFEST_RELATIVE_PATH = Path(
    "development/stage383/"
    "stage383_recovery_session_manifest.json"
)

STAGE383_WORKFLOW_RELATIVE_PATH = Path(
    ".github/workflows/"
    "stage383-policy-bound-recovery-orchestration.yml"
)

STAGE382_POLICY_RELATIVE_PATH = Path(
    "development/stage382/policy-profiles/"
    "qsp-dual-timestamp-final-acceptance-v1.json"
)


def load_json(path: Path) -> dict[str, Any]:
    data = json.loads(path.read_text(encoding="utf-8"))

    if not isinstance(data, dict):
        raise TypeError(f"JSON root must be object: {path}")

    return data


def write_json(path: Path, value: dict[str, Any]) -> None:
    path.write_text(
        json.dumps(
            value,
            ensure_ascii=False,
            indent=2,
            sort_keys=True,
        )
        + "\n",
        encoding="utf-8",
        newline="\n",
    )


class Stage384FailClosedTests(unittest.TestCase):
    temporary_directory: tempfile.TemporaryDirectory[str]
    worktree: Path

    def setUp(self) -> None:
        self.temporary_directory = tempfile.TemporaryDirectory()
        self.worktree = Path(self.temporary_directory.name) / "repo"

        shutil.copytree(
            REPOSITORY_ROOT,
            self.worktree,
            ignore=shutil.ignore_patterns(
                ".git",
                "__pycache__",
                "*.pyc",
            ),
        )

    def tearDown(self) -> None:
        self.temporary_directory.cleanup()

    def run_verifier(self) -> tuple[int, dict[str, Any]]:
        completed = subprocess.run(
            [
                sys.executable,
                str(self.worktree / VERIFIER_RELATIVE_PATH),
            ],
            cwd=self.worktree,
            check=False,
            capture_output=True,
            text=True,
            encoding="utf-8",
        )

        result_path = self.worktree / RESULT_RELATIVE_PATH

        self.assertTrue(
            result_path.is_file(),
            msg=(
                "Stage384 result was not generated.\n"
                f"stdout:\n{completed.stdout}\n"
                f"stderr:\n{completed.stderr}"
            ),
        )

        return completed.returncode, load_json(result_path)

    def test_unchanged_state_is_verified(self) -> None:
        exit_code, result = self.run_verifier()

        self.assertEqual(exit_code, 0)
        self.assertEqual(
            result.get("decision"),
            "continuous_trust_state_verified_upstream_pending",
        )
        self.assertEqual(
            result.get("verification_status"),
            "verified_unchanged_upstream_pending",
        )
        self.assertFalse(result.get("change_detected"))
        self.assertEqual(result.get("detected_change_count"), 0)
        self.assertFalse(result.get("reverification_required"))
        self.assertFalse(result.get("eligibility_invalidated"))
        self.assertEqual(result.get("critical_failure_count"), 0)

    def test_missing_monitored_artifact_invalidates(self) -> None:
        target = self.worktree / STAGE382_POLICY_RELATIVE_PATH
        target.unlink()

        exit_code, result = self.run_verifier()

        self.assertEqual(exit_code, 1)
        self.assertEqual(
            result.get("decision"),
            "formal_acceptance_eligibility_invalidated",
        )
        self.assertTrue(result.get("change_detected"))
        self.assertTrue(result.get("reverification_required"))
        self.assertTrue(result.get("eligibility_invalidated"))
        self.assertGreaterEqual(
            result.get("critical_change_count", 0),
            1,
        )

    def test_material_workflow_change_requires_reverification(
        self,
    ) -> None:
        workflow_path = (
            self.worktree / STAGE383_WORKFLOW_RELATIVE_PATH
        )

        workflow_path.write_text(
            workflow_path.read_text(encoding="utf-8")
            + "\n# Stage384 material-change test\n",
            encoding="utf-8",
            newline="\n",
        )

        exit_code, result = self.run_verifier()

        self.assertEqual(exit_code, 1)
        self.assertEqual(
            result.get("decision"),
            "trust_state_change_reverification_required",
        )
        self.assertTrue(result.get("change_detected"))
        self.assertTrue(result.get("reverification_required"))
        self.assertFalse(result.get("eligibility_invalidated"))
        self.assertGreaterEqual(
            result.get("material_change_count", 0),
            1,
        )

    def test_critical_policy_change_invalidates(self) -> None:
        policy_path = (
            self.worktree / STAGE382_POLICY_RELATIVE_PATH
        )

        policy_path.write_text(
            policy_path.read_text(encoding="utf-8")
            + "\n",
            encoding="utf-8",
            newline="\n",
        )

        exit_code, result = self.run_verifier()

        self.assertEqual(exit_code, 1)
        self.assertEqual(
            result.get("decision"),
            "formal_acceptance_eligibility_invalidated",
        )
        self.assertTrue(result.get("eligibility_invalidated"))
        self.assertGreaterEqual(
            result.get("critical_change_count", 0),
            1,
        )

    def test_policy_sha256_tampering_fails_closed(self) -> None:
        record_path = (
            self.worktree / POLICY_SHA256_RELATIVE_PATH
        )

        record_path.write_text(
            (
                "0" * 64
                + "  "
                + POLICY_RELATIVE_PATH.as_posix()
                + "\n"
            ),
            encoding="utf-8",
            newline="\n",
        )

        exit_code, result = self.run_verifier()

        self.assertEqual(exit_code, 2)
        self.assertEqual(result.get("decision"), "fail_closed")
        self.assertIn(
            "policy_sha256_valid",
            result.get("critical_failures", []),
        )
        self.assertTrue(result.get("eligibility_invalidated"))

    def test_baseline_sha256_tampering_fails_closed(self) -> None:
        record_path = (
            self.worktree / BASELINE_SHA256_RELATIVE_PATH
        )

        record_path.write_text(
            (
                "0" * 64
                + "  "
                + BASELINE_RELATIVE_PATH.as_posix()
                + "\n"
            ),
            encoding="utf-8",
            newline="\n",
        )

        exit_code, result = self.run_verifier()

        self.assertEqual(exit_code, 2)
        self.assertEqual(result.get("decision"), "fail_closed")
        self.assertIn(
            "baseline_file_sha256_valid",
            result.get("critical_failures", []),
        )
        self.assertTrue(result.get("eligibility_invalidated"))

    def test_stage383_session_mismatch_invalidates(self) -> None:
        result_path = (
            self.worktree / STAGE383_RESULT_RELATIVE_PATH
        )

        stage383 = load_json(result_path)
        stage383["recovery_session"]["session_id"] = (
            "stage383-invalid-session"
        )

        write_json(result_path, stage383)

        exit_code, result = self.run_verifier()

        self.assertEqual(exit_code, 1)
        self.assertEqual(
            result.get("decision"),
            "formal_acceptance_eligibility_invalidated",
        )
        self.assertTrue(result.get("eligibility_invalidated"))

        change_types = {
            change.get("change_type")
            for change in result.get("detected_changes", [])
        }

        self.assertIn(
            "stage383_recovery_session_id_mismatch",
            change_types,
        )

    def test_manifest_session_mismatch_invalidates(self) -> None:
        manifest_path = (
            self.worktree / STAGE383_MANIFEST_RELATIVE_PATH
        )

        manifest = load_json(manifest_path)
        manifest["recovery_session"]["session_id"] = (
            "stage383-invalid-manifest-session"
        )

        write_json(manifest_path, manifest)

        exit_code, result = self.run_verifier()

        self.assertEqual(exit_code, 1)
        self.assertEqual(
            result.get("decision"),
            "formal_acceptance_eligibility_invalidated",
        )
        self.assertTrue(result.get("eligibility_invalidated"))

        change_types = {
            change.get("change_type")
            for change in result.get("detected_changes", [])
        }

        self.assertIn(
            "stage383_manifest_session_id_mismatch",
            change_types,
        )

    def test_stage383_critical_failure_invalidates(self) -> None:
        result_path = (
            self.worktree / STAGE383_RESULT_RELATIVE_PATH
        )

        stage383 = load_json(result_path)
        stage383["critical_failure_count"] = 1

        write_json(result_path, stage383)

        exit_code, result = self.run_verifier()

        self.assertEqual(exit_code, 1)
        self.assertEqual(
            result.get("decision"),
            "formal_acceptance_eligibility_invalidated",
        )
        self.assertTrue(result.get("eligibility_invalidated"))

        change_types = {
            change.get("change_type")
            for change in result.get("detected_changes", [])
        }

        self.assertIn(
            "stage383_critical_failure_detected",
            change_types,
        )

    def test_baseline_embedded_hash_tampering_fails_closed(
        self,
    ) -> None:
        baseline_path = (
            self.worktree / BASELINE_RELATIVE_PATH
        )

        baseline = load_json(baseline_path)
        baseline["baseline_sha256"] = "0" * 64
        write_json(baseline_path, baseline)

        # Update only the external file record so the embedded-hash
        # verification is the specific failing check.
        import hashlib

        record_path = (
            self.worktree / BASELINE_SHA256_RELATIVE_PATH
        )

        digest = hashlib.sha256(
            baseline_path.read_bytes()
        ).hexdigest()

        record_path.write_text(
            (
                f"{digest}  "
                f"{BASELINE_RELATIVE_PATH.as_posix()}\n"
            ),
            encoding="utf-8",
            newline="\n",
        )

        exit_code, result = self.run_verifier()

        self.assertEqual(exit_code, 2)
        self.assertEqual(result.get("decision"), "fail_closed")
        self.assertIn(
            "embedded_baseline_sha256_valid",
            result.get("critical_failures", []),
        )


if __name__ == "__main__":
    unittest.main(verbosity=2)
