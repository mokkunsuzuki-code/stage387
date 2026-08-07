#!/usr/bin/env python3

from __future__ import annotations

import hashlib
import json
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path
from typing import Any


SOURCE_ROOT = Path(__file__).resolve().parents[2]


def canonical_json_bytes(value: Any) -> bytes:
    return json.dumps(
        value,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")


def write_json(path: Path, data: Any) -> None:
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


def write_sha256_record(
    root: Path,
    target: Path,
    record: Path,
) -> None:
    digest = hashlib.sha256(
        target.read_bytes()
    ).hexdigest()

    relative_target = target.relative_to(
        root
    ).as_posix()

    record.write_text(
        f"{digest}  {relative_target}\n",
        encoding="utf-8",
        newline="\n",
    )


class Stage385FailClosedTests(
    unittest.TestCase
):
    maxDiff = None

    def setUp(self) -> None:
        self.temp_dir = tempfile.TemporaryDirectory()

        self.root = Path(
            self.temp_dir.name
        ) / "repo"

        shutil.copytree(
            SOURCE_ROOT,
            self.root,
            ignore=shutil.ignore_patterns(
                ".git",
                "__pycache__",
            ),
        )

        self.verifier = (
            self.root
            / "development/stage385/"
            / "verify_stage385_cryptographic_agility.py"
        )

        self.policy = (
            self.root
            / "development/stage385/"
            / "stage385_cryptographic_agility_policy.json"
        )

        self.policy_sha = (
            self.root
            / "development/stage385/"
            / "stage385_cryptographic_agility_policy.sha256"
        )

        self.inventory = (
            self.root
            / "development/stage385/"
            / "stage385_cryptographic_inventory.json"
        )

        self.inventory_sha = (
            self.root
            / "development/stage385/"
            / "stage385_cryptographic_inventory.sha256"
        )

        self.stage384_result = (
            self.root
            / "development/stage384/"
            / "stage384_change_detection_result.json"
        )

        self.stage384_result_sha = (
            self.root
            / "development/stage384/"
            / "stage384_change_detection_result.sha256"
        )

        self.output = (
            self.root
            / "development/stage385/"
            / "stage385_pqc_migration_readiness_result.json"
        )

    def tearDown(self) -> None:
        self.temp_dir.cleanup()

    def run_verifier(
        self,
    ) -> tuple[
        subprocess.CompletedProcess[str],
        dict[str, Any],
    ]:
        completed = subprocess.run(
            [
                "python3",
                str(self.verifier),
            ],
            cwd=self.root,
            text=True,
            capture_output=True,
            check=False,
        )

        self.assertTrue(
            self.output.is_file(),
            msg=(
                "Stage385 verifier did not create "
                "a result file.\n"
                + completed.stdout
                + "\n"
                + completed.stderr
            ),
        )

        result = json.loads(
            self.output.read_text(
                encoding="utf-8"
            )
        )

        return completed, result

    def load_inventory(
        self,
    ) -> dict[str, Any]:
        return json.loads(
            self.inventory.read_text(
                encoding="utf-8"
            )
        )

    def save_inventory(
        self,
        data: dict[str, Any],
    ) -> None:
        write_json(
            self.inventory,
            data,
        )

        write_sha256_record(
            self.root,
            self.inventory,
            self.inventory_sha,
        )

    def load_stage384_result(
        self,
    ) -> dict[str, Any]:
        return json.loads(
            self.stage384_result.read_text(
                encoding="utf-8"
            )
        )

    def save_stage384_result(
        self,
        data: dict[str, Any],
    ) -> None:
        data.pop(
            "result_sha256",
            None,
        )

        data["result_sha256"] = (
            hashlib.sha256(
                canonical_json_bytes(data)
            ).hexdigest()
        )

        write_json(
            self.stage384_result,
            data,
        )

        write_sha256_record(
            self.root,
            self.stage384_result,
            self.stage384_result_sha,
        )

    def test_current_state_is_verified_inventory_gap(
        self,
    ) -> None:
        completed, result = (
            self.run_verifier()
        )

        self.assertEqual(
            completed.returncode,
            0,
        )

        self.assertEqual(
            result.get("decision"),
            "cryptographic_inventory_incomplete",
        )

        self.assertEqual(
            result.get(
                "critical_failure_count"
            ),
            0,
        )

        state = result.get(
            "cryptographic_state",
            {},
        )

        self.assertEqual(
            state.get(
                "inventory_incomplete_count"
            ),
            4,
        )

        self.assertEqual(
            state.get(
                "migration_required_count"
            ),
            2,
        )

    def test_policy_sha256_tampering_fails_closed(
        self,
    ) -> None:
        self.policy.write_text(
            self.policy.read_text(
                encoding="utf-8"
            )
            + "\n",
            encoding="utf-8",
            newline="\n",
        )

        completed, result = (
            self.run_verifier()
        )

        self.assertNotEqual(
            completed.returncode,
            0,
        )

        self.assertEqual(
            result.get("decision"),
            "fail_closed",
        )

        self.assertGreater(
            result.get(
                "critical_failure_count",
                0,
            ),
            0,
        )

    def test_inventory_sha256_tampering_fails_closed(
        self,
    ) -> None:
        self.inventory.write_text(
            self.inventory.read_text(
                encoding="utf-8"
            )
            + "\n",
            encoding="utf-8",
            newline="\n",
        )

        completed, result = (
            self.run_verifier()
        )

        self.assertNotEqual(
            completed.returncode,
            0,
        )

        self.assertEqual(
            result.get("decision"),
            "fail_closed",
        )

    def test_duplicate_asset_id_fails_closed(
        self,
    ) -> None:
        data = self.load_inventory()

        data["assets"][1]["asset_id"] = (
            data["assets"][0]["asset_id"]
        )

        self.save_inventory(data)

        completed, result = (
            self.run_verifier()
        )

        self.assertNotEqual(
            completed.returncode,
            0,
        )

        self.assertEqual(
            result.get("decision"),
            "fail_closed",
        )

    def test_private_key_publication_claim_fails_closed(
        self,
    ) -> None:
        data = self.load_inventory()

        data[
            "publication_boundary"
        ][
            "private_key_material_included"
        ] = True

        self.save_inventory(data)

        completed, result = (
            self.run_verifier()
        )

        self.assertNotEqual(
            completed.returncode,
            0,
        )

        self.assertEqual(
            result.get("decision"),
            "fail_closed",
        )

    def test_entire_system_quantum_safe_claim_fails_closed(
        self,
    ) -> None:
        data = self.load_inventory()

        data[
            "current_migration_observation"
        ][
            "entire_system_quantum_safe"
        ] = True

        self.save_inventory(data)

        completed, result = (
            self.run_verifier()
        )

        self.assertNotEqual(
            completed.returncode,
            0,
        )

        self.assertEqual(
            result.get("decision"),
            "fail_closed",
        )

    def test_stage384_change_requires_reverification(
        self,
    ) -> None:
        data = self.load_stage384_result()

        data["change_detected"] = True
        data["reverification_required"] = True

        self.save_stage384_result(data)

        completed, result = (
            self.run_verifier()
        )

        self.assertNotEqual(
            completed.returncode,
            0,
        )

        self.assertEqual(
            result.get("decision"),
            "stage384_change_requires_reverification",
        )

    def test_missing_verified_evidence_fails_closed(
        self,
    ) -> None:
        evidence_path = (
            self.root
            / "docs/mldsa-production/"
            / "stage375_mldsa65_execution_receipt.json"
        )

        self.assertTrue(
            evidence_path.is_file()
        )

        evidence_path.unlink()

        completed, result = (
            self.run_verifier()
        )

        self.assertNotEqual(
            completed.returncode,
            0,
        )

        self.assertEqual(
            result.get("decision"),
            "fail_closed",
        )

    def test_prohibited_algorithm_detected(
        self,
    ) -> None:
        data = self.load_inventory()

        target = next(
            asset
            for asset in data["assets"]
            if asset["asset_id"]
            == "stage374-sigstore-signature"
        )

        target["algorithm_status"] = (
            "prohibited"
        )

        target["migration_state"] = (
            "blocked"
        )

        self.save_inventory(data)

        completed, result = (
            self.run_verifier()
        )

        self.assertEqual(
            completed.returncode,
            0,
        )

        self.assertEqual(
            result.get("decision"),
            "prohibited_algorithm_detected",
        )

        state = result.get(
            "cryptographic_state",
            {},
        )

        self.assertEqual(
            state.get(
                "prohibited_algorithm_count"
            ),
            1,
        )

    def test_complete_inventory_exposes_migration_required(
        self,
    ) -> None:
        data = self.load_inventory()

        for asset in data["assets"]:
            if (
                asset.get(
                    "algorithm_status"
                )
                == "evidence_required"
            ):
                asset[
                    "algorithm_status"
                ] = "allowed"

            if (
                asset.get(
                    "algorithm_identifier"
                )
                == "unknown"
            ):
                asset[
                    "algorithm_identifier"
                ] = (
                    "test-resolved-algorithm"
                )

            if (
                asset.get(
                    "migration_state"
                )
                == "not_inventoried"
            ):
                asset[
                    "migration_state"
                ] = "identified"

        self.save_inventory(data)

        completed, result = (
            self.run_verifier()
        )

        self.assertEqual(
            completed.returncode,
            0,
        )

        self.assertEqual(
            result.get("decision"),
            "pqc_migration_required",
        )

        state = result.get(
            "cryptographic_state",
            {},
        )

        self.assertEqual(
            state.get(
                "inventory_incomplete_count"
            ),
            0,
        )

        self.assertEqual(
            state.get(
                "migration_required_count"
            ),
            2,
        )


if __name__ == "__main__":
    unittest.main(verbosity=2)
