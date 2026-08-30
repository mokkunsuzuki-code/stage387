<!-- STAGE383_ROOT_README_START -->
# Stage383: Policy-Bound Recovery Orchestration & Formal Acceptance Eligibility Gate

Stage383 extends Stage382 by binding the existing Stage377 through Stage382
verification records to one deterministic recovery session.

It evaluates whether the complete recovery chain satisfies the requirements
for formal-acceptance eligibility.

Stage383 does not issue formal acceptance and does not declare pipeline
completion.

## What Stage383 Adds

Stage383 adds the following public verification capabilities:

1. A fixed recovery-orchestration contract
2. A deterministic recovery-session identifier
3. Stage377 through Stage382 input and hash binding
4. Fixed-order downstream reverification requirements
5. Detection of missing, mixed, skipped, stale, or tampered artifacts
6. Formal-acceptance eligibility evaluation
7. Separation of eligibility from certificate issuance
8. Ten automated Fail-Closed tests
9. A GitHub Actions verification workflow
10. Public verification evidence under `docs/verification/stage383/`

## Required Recovery Order

Stage377 dual-timestamp final acceptance
        |
        v
Stage378 QKD safety metadata reverification
        |
        v
Stage379 scoped total verification
        |
        v
Stage380 deterministic offline verification
        |
        v
Stage381 cross-platform reverification
        |
        v
Stage382 policy-bound verification
        |
        v
Stage383 formal-acceptance eligibility decision

The order is fixed.

Stage skipping, out-of-order execution, mixed workflow-run artifacts, and
automatic formal-acceptance issuance are prohibited.

## Current Stage383 State

The current Stage377 result remains:

decision = rfc3161_verified_opentimestamps_pending
verified_proof_count = 1
effective_final_acceptance = false

Therefore, Stage383 currently reports:

decision = upstream_finalization_pending
verification_status = verified_pending_upstream
recovery_phase = waiting_for_stage377
critical_failure_count = 0

Formal-acceptance boundary:

formal_acceptance_eligible = false
formal_acceptance_issued = false
formal_acceptance = false
pipeline_completed = false
public_release_allowed = false

This is an intended Fail-Closed waiting state.

Stage383 does not fabricate Stage377 completion and does not convert the
pending OpenTimestamps proof into a verified proof.

## Deterministic Recovery Session

Current recovery-session identifier:

stage383-66bce0a526782ef0e49221e70bcc939268f0d04e6e2e86e34aea9aed6caf5505

The identifier is derived from fixed verification inputs and excludes runtime
timestamps, random values, usernames, hostnames, and absolute local paths.

## Verification and Test State

The current local Stage383 validation reports:

Python syntax validation = passed
Fail-Closed tests = 10 passed
Stage383 verifier exit code = 0
critical_failure_count = 0
contract SHA-256 = valid
result SHA-256 = valid
manifest SHA-256 = valid
public source/evidence hashes = identical
## Public Stage383 Evidence

The public verification files are located at:

docs/verification/stage383/
├── stage383_recovery_orchestration_contract.json
├── stage383_recovery_orchestration_contract.sha256
├── stage383_formal_acceptance_eligibility_result.json
├── stage383_formal_acceptance_eligibility_result.sha256
├── stage383_recovery_session_manifest.json
└── stage383_recovery_session_manifest.sha256

The Stage383 GitHub Actions workflow is:

.github/workflows/stage383-policy-bound-recovery-orchestration.yml
## Formal-Acceptance Boundary

Stage383 distinguishes between:

formal_acceptance_eligible

and:

formal_acceptance_issued

Eligibility does not equal issuance.

Even when every eligibility condition is eventually satisfied, Stage383
requires a separate manual or independently verified issuance transition.

Stage383 itself does not issue the final production certificate.

## Preservation Boundary

Stage383 does not replace, modify, or overwrite the established Stage377
through Stage382 verification records.

The complete Stage382 README and all inherited earlier documentation remain
preserved below this Stage383 section.

## Security and Publication Boundary

The following directories must remain private and must not be pushed to GitHub:

core/
private_core/
private/
secrets/
keys/
imported/

Stage383 publishes no private key, secret, credential, token, raw QKD key,
derived QKD secret, raw timestamp binary, private runner output, or
confidential evidence.

Only reviewed public source code, verification metadata, SHA-256 records,
results, manifests, and documentation may be published.

## License

This project is licensed under the MIT License.

See the repository-level LICENSE file for the complete license text.

The MIT License does not override confidentiality requirements, publication
boundaries, security controls, private-material restrictions, upstream
evidence restrictions, or third-party licenses.

<!-- STAGE383_ROOT_README_END -->

## Preserved Stage382 Foundation

# Stage382: Upstream Finalization Recovery & Policy Activation Gate

日本語：

# 上流最終確定回復・ポリシー有効化ゲート

<!-- STAGE382_ROOT_README_START -->

Stage382 extends Stage381 by binding the unresolved Stage377
dual-timestamp final-acceptance requirements to a fixed,
versioned policy profile.

Stage382 preserves Stage377, Stage378, Stage379, Stage380, and
Stage381. It does not replace or overwrite their verification records.

## What Stage382 Adds

Stage382 adds:

1. A versioned dual-timestamp final-acceptance policy
2. SHA-256 binding of the policy profile
3. Stage377 completion-state observation
4. Mandatory Stage378 reverification after Stage377 completion
5. Mandatory Stage379, Stage380, and Stage381 reverification
6. Fail-Closed handling of policy and publication-boundary violations
7. A policy-activation manifest binding Stage377 through Stage381

## Required Recovery Order

```text
Stage377 dual-timestamp final acceptance
                    |
                    v
Stage378 QKD safety metadata rebinding
                    |
                    v
Stage379 scoped total verification
                    |
                    v
Stage380 deterministic offline verification
                    |
                    v
Stage381 cross-platform reverification
                    |
                    v
Stage382 policy-bound verification
```

## Current State

```text
Stage377 decision:
rfc3161_verified_opentimestamps_pending

Stage377 verified proof count:
1

Stage377 effective final acceptance:
false

Stage378 ready:
false

Stage382 decision:
policy_bound_final_acceptance_pending

Stage382 verification status:
verified_pending_upstream

Critical failure count:
0
```

This is the intended Fail-Closed waiting state.

Stage382 does not generate a replacement OpenTimestamps proof and does
not weaken the requirement for two independently verified timestamp
proofs.

## Versioned Policy Profile

```text
Profile:
qsp-dual-timestamp-final-acceptance-v1

Profile version:
1.0.0

Policy SHA-256:
1819dc41cee56da7f7faabdbdc6dab44326054c9197bf5bd6c52286b7e8e9ea5
```

The policy requires:

- RFC3161 verification
- OpenTimestamps verification
- `verified_proof_count == 2`
- `effective_final_acceptance == true`
- Stage378 QKD metadata rebinding
- Stage379 scoped reverification
- Stage380 deterministic offline reverification
- Stage381 Ubuntu, Windows, and macOS reverification
- no automatic formal-acceptance upgrade
- no publication of private or secret material

## Formal-Acceptance Boundary

Stage382 remains development-only.

```text
formal_acceptance = false
pipeline_completed = false
public_release_allowed = false
```

A valid policy-integrity check is not equivalent to production formal
acceptance.

## Security and Publication Boundary

The following directories must remain private:

```text
core/
private_core/
private/
secrets/
keys/
imported/
```

Stage382 does not publish private keys, credentials, authentication
tokens, raw QKD secret material, raw timestamp proof binaries, or
private-core material.

## Public Stage382 Evidence

Public Stage382 evidence is available under:

```text
docs/verification/stage382/
```

It includes:

- the versioned policy profile
- the policy SHA-256 record
- the upstream-finalization result
- the result SHA-256 record
- the policy-activation manifest
- the manifest SHA-256 record

## License

This repository is licensed under the MIT License.

See the repository-level `LICENSE` file for the complete license text.

<!-- STAGE382_ROOT_README_END -->

## Preserved Stage381 Foundation

The existing Stage381 documentation and inherited Stage380 foundation
remain preserved below.
Preserved Stage381 Foundation

The existing Stage381 documentation and inherited Stage380 foundation
remain preserved below.

# Stage381: Deterministic Reverification & Reproducibility Gate

Stage381 extends Stage380 with a cross-platform deterministic
reverification and reproducibility gate.

It verifies whether the same fixed verification input produces the same
material result on:

- Ubuntu
- Windows
- macOS

Stage381 does not replace, rewrite, or upgrade the Stage380 verification
scope. It preserves the Stage380 independent offline verification package
and adds a fail-closed cross-platform comparison layer.

## What Stage381 Adds

Stage381 adds the following public verification components:

1. A fixed canonicalization profile
2. Deterministic environment-result generation
3. Ubuntu, Windows, and macOS verification through GitHub Actions
4. Cross-platform comparison of required result fields
5. A Stage381 verification-package contract
6. SHA-256 binding of the contract and verification records
7. A final fail-closed package verifier
8. Downloadable GitHub Actions verification artifacts

## Verification Flow

```text
Stage380 independent offline verification package
                    |
                    v
      Fixed Stage381 canonicalization rules
                    |
                    v
       Ubuntu / Windows / macOS execution
                    |
                    v
       Deterministic environment results
                    |
                    v
        Cross-platform field comparison
                    |
                    v
       Stage381 final package verification
```

## Required Cross-Platform Conditions

Stage381 requires all three configured platforms to be present.

The comparison must confirm:

- the same fixed verification input was used
- the same decision was produced
- the same verification status was produced
- the same package-integrity result was produced
- the same critical-failure count was produced
- the same process exit code was produced
- the same Stage380 result SHA-256 was bound
- the same canonical result SHA-256 was produced

If a required platform result is missing, malformed, inconsistent, or not
bound to the required Stage380 input, Stage381 remains fail-closed.

## One-Command Local Verification

A local machine can validate the Stage381 package structure with:

```bash
python3 development/stage381/verify_stage381_cross_platform_package.py
```

A single local machine verifies only the result available on that machine.

Formal cross-platform verification requires Ubuntu, Windows, and macOS
results. The included GitHub Actions workflow provides those environments
without requiring the operator to own three separate computers.

## GitHub Actions Verification

The workflow is:

```text
.github/workflows/stage381-cross-platform-reverification.yml
```

It performs:

1. Deterministic verification on Ubuntu
2. Deterministic verification on Windows
3. Deterministic verification on macOS
4. Artifact collection
5. Cross-platform comparison
6. Stage381 contract validation
7. Final package verification
8. Verification-package artifact upload

## License

This project is released under the MIT License.

See the `LICENSE` file included in this repository for the complete license
text.

## Security and Publication Boundary

Stage381 publishes only the files required for deterministic verification
and audit.

The following material must remain outside the public repository:

- `core/`
- `private_core/`
- `private/`
- `secrets/`
- `keys/`
- `imported/`
- private keys
- credentials
- unpublished raw evidence
- confidential execution material

Stage381 does not publish attack code, harmful payloads, secret keys, or
private-core implementation material.

## Fail-Closed Meaning

A fail-closed result does not automatically mean that the verifier
malfunctioned.

Before all three operating-system results exist, Stage381 must report that
cross-platform reverification is not verified.

Stage381 may report successful cross-platform reproducibility only after all
required platform records exist and all required comparison fields match.

## Current Verification Status

The Stage381 implementation and GitHub Actions workflow are present.

Formal Stage381 cross-platform completion requires a successful GitHub
Actions execution with matching Ubuntu, Windows, and macOS results.

Until that execution succeeds, cross-platform reverification must remain
unverified.

## Inherited Stage380 Foundation

The following Stage380 documentation is retained because Stage381 extends
rather than replaces the Stage380 independent offline verification package.
Stage380 extends Stage379 by packaging the established verification scope into a deterministic offline verification contract.

Stage380 does not replace or rewrite Stage379. It preserves the Stage379 development snapshot and verifies the package from an independent, offline, fail-closed perspective.

## Purpose

Stage380 adds two core capabilities:

1. Independent Verification Package Contract
2. Deterministic Offline Core Verifier

The purpose is to make the Stage379 verification package independently reproducible without network access and without changing the established verification scope.

## Current State

Stage380 is currently development-only.

The current decision is:

`development_package_verified_upstream_pending`

Current verified state:

- package integrity verified: `true`
- formal independent verification: `false`
- formal acceptance: `false`
- pipeline completed: `false`
- public release allowed: `false`
- critical failure count: `0`

Formal independent verification remains pending because the upstream formal acceptance conditions are not yet complete.

## Upstream Conditions

Stage380 depends on the established Stage377, Stage378, and Stage379 results.

Required formal conditions include:

### Stage377

- `verified_proof_count == 2`
- `effective_final_acceptance == true`

### Stage378

- `qkd_metadata_bound == true`
- Stage377 result hash valid
- Stage378 hash chain valid
- QKD publication boundary valid
- QKD evidence classification complete

### Stage379

- `formal_acceptance == true`
- `pipeline_completed == true`
- `critical_integrity_valid == true`

Until these conditions are satisfied, Stage380 must remain development-only and fail closed against any formal acceptance claim.

## Independent Verification Package Contract

The Stage380 contract is:

`development/stage380/stage380_independent_verification_package_contract.json`

The contract defines:

- source stage
- source snapshot manifest
- required input files
- deterministic offline execution
- package locking
- scope-reduction prohibition
- fail-closed behavior
- development-only state
- formal acceptance prohibition

The contract is fixed by:

`development/stage380/stage380_independent_verification_package_contract.sha256`

Verification command:

```bash
shasum -a 256 -c development/stage380/stage380_independent_verification_package_contract.sha256
```

## Deterministic Offline Core Verifier

The Stage380 verifier is:

development/stage380/verify_stage380_independent_package.py

The verifier performs the following checks:

Stage380 contract presence
Stage380 contract SHA-256 verification
SHA-256 record path verification
contract policy validation
required input presence checks
required input SHA-256 calculation
Stage379 snapshot manifest verification
Stage379 snapshot artifact hash verification
Stage379 snapshot artifact size verification
duplicate artifact-path detection
Stage377 state observation
Stage378 state observation
Stage379 state observation
Stage379 critical-integrity validation
Stage379 development certificate validation
formal-acceptance readiness evaluation
fail-closed decision generation
deterministic result generation

Run the verifier with:

python3 development/stage380/verify_stage380_independent_package.py

Expected current decision:

decision=development_package_verified_upstream_pending
package_integrity_verified=true
formal_independent_verification=false
critical_failure_count=0
## Deterministic Output

Stage380 is designed so that the same input produces the same output.

The result intentionally excludes:

runtime timestamps
random values
hostnames
usernames
absolute local paths
network-derived values

Deterministic verification can be checked with:

FIRST_HASH=$(shasum -a 256 development/stage380/stage380_independent_verification_result.json | awk '{print $1}')
python3 development/stage380/verify_stage380_independent_package.py >/dev/null
SECOND_HASH=$(shasum -a 256 development/stage380/stage380_independent_verification_result.json | awk '{print $1}')
printf "FIRST_HASH=%s\nSECOND_HASH=%s\n" "$FIRST_HASH" "$SECOND_HASH"
[ "$FIRST_HASH" = "$SECOND_HASH" ] && echo "DETERMINISTIC_OUTPUT_VALID"
## Fail-Closed Principle

Stage380 must return fail_closed when a critical verification requirement fails.

Examples include:

missing Stage380 contract
invalid contract JSON
contract SHA-256 mismatch
invalid SHA-256 record path
missing required input
missing Stage379 snapshot manifest
Stage379 snapshot artifact missing
Stage379 snapshot artifact hash mismatch
Stage379 snapshot artifact size mismatch
duplicate snapshot artifact path
invalid Stage379 critical integrity
invalid development certificate type
contract policy mismatch
scope reduction enabled
offline mode disabled
package lock disabled

Stage380 does not convert missing, unknown, pending, or invalid evidence into verified evidence.

## Verification Result

The deterministic verification result is:

development/stage380/stage380_independent_verification_result.json

It contains:

decision
verification status
package-integrity status
formal-verification status
upstream state
contract SHA-256
snapshot SHA-256
required-input SHA-256 values
verification checks
critical failures
deterministic result SHA-256

The external result hash record is:

development/stage380/stage380_independent_verification_result.sha256

Verification command:

shasum -a 256 -c development/stage380/stage380_independent_verification_result.sha256
## Verification Manifest

The Stage380 manifest is:

development/stage380/stage380_independent_verification_manifest.json

The manifest records:

development policy
verification contract
deterministic verifier
verification result
verification certificate
actual SHA-256 values
actual file sizes
artifact count

The manifest is fixed by:

development/stage380/stage380_independent_verification_manifest.sha256

Verification command:

shasum -a 256 -c development/stage380/stage380_independent_verification_manifest.sha256
## Verification Certificate

The Stage380 development certificate is:

development/stage380/stage380_independent_verification_certificate.json

Certificate type:

development_independent_verification_certificate

The certificate does not claim formal independent verification.

It records that:

deterministic offline package verification completed
package integrity was verified
formal independent verification remains pending
upstream formal acceptance remains incomplete
pipeline completion is not claimed

The certificate is fixed by:

development/stage380/stage380_independent_verification_certificate.sha256

Verification command:

shasum -a 256 -c development/stage380/stage380_independent_verification_certificate.sha256
## Stage379 Preservation

Stage380 preserves and consumes the Stage379 development package.

Primary Stage379 inputs include:

development/stage379/stage379_development_snapshot_manifest.json
development/stage379/stage379_development_acceptance_certificate.json
development/stage379/stage379_scoped_total_verification_result.json
development/stage379/stage379_verification_scope_policy.json

Stage380 does not modify these Stage379 records.

The previous root README is preserved at:

development/stage380/README.stage377-preserved.md

## Public and Private Boundaries

Stage380 preserves the existing Git exclusion rules.

The following directories must remain private and must not be pushed to GitHub:

core/
private_core/
private/
secrets/
keys/
imported/

Stage380 must not publish:

private keys
secret seeds
access tokens
OIDC tokens
GitHub tokens
raw QKD key material
private runner output
unrestricted external command input
raw confidential evidence

Only reviewed metadata and approved public evidence may be placed under docs/.

## Offline Verification Boundary

The Stage380 verifier requires no network access.

It does not:

contact timestamp authorities
contact blockchain nodes
contact Sigstore or Rekor
download GitHub Actions artifacts
fetch external evidence
execute user-supplied shell commands
generate or expose secret material

Stage380 verifies the locally available package as provided.

## Directory Structure
development/stage380/
├── README.stage377-preserved.md
├── stage380_independent_verification_package_contract.json
├── stage380_independent_verification_package_contract.sha256
├── verify_stage380_independent_package.py
├── stage380_independent_verification_result.json
├── stage380_independent_verification_result.sha256
├── stage380_independent_verification_manifest.json
├── stage380_independent_verification_manifest.sha256
├── stage380_independent_verification_certificate.json
└── stage380_independent_verification_certificate.sha256

Root development policy:

.stage380-development-policy.json
## Verification Sequence

Recommended verification sequence:

python3 -m json.tool .stage380-development-policy.json >/dev/null

python3 -m json.tool \
development/stage380/stage380_independent_verification_package_contract.json \
>/dev/null

shasum -a 256 -c \
development/stage380/stage380_independent_verification_package_contract.sha256

python3 -m py_compile \
development/stage380/verify_stage380_independent_package.py

python3 \
development/stage380/verify_stage380_independent_package.py

shasum -a 256 -c \
development/stage380/stage380_independent_verification_result.sha256

python3 -m json.tool \
development/stage380/stage380_independent_verification_manifest.json \
>/dev/null

shasum -a 256 -c \
development/stage380/stage380_independent_verification_manifest.sha256

python3 -m json.tool \
development/stage380/stage380_independent_verification_certificate.json \
>/dev/null

shasum -a 256 -c \
development/stage380/stage380_independent_verification_certificate.sha256
## Decision Model
development_package_verified_upstream_pending

The Stage380 package is internally valid, but upstream formal acceptance conditions remain incomplete.

independent_verification_package_ready

The Stage380 package is internally valid and all required upstream formal acceptance conditions are satisfied.

This decision must not be emitted unless the actual Stage377, Stage378, and Stage379 records satisfy the contract.

fail_closed

One or more critical integrity, policy, hash, file, snapshot, or certificate checks failed.

## Security Properties

Stage380 provides the following development-stage properties:

deterministic local verification
offline operation
package integrity validation
artifact hash validation
artifact size validation
duplicate-path detection
upstream-state observation
fail-closed decisions
scope-lock enforcement
scope-reduction prohibition
private-boundary preservation
no formal claim while upstream is pending

Stage380 does not prove that an external organization or independent third party has executed the verifier.

That requires an actual independent execution environment and independently retained evidence.

## Current Limitations

Current limitations include:

Stage377 has not yet reached dual verified timestamp acceptance
Stage378 QKD metadata binding remains pending
Stage379 formal acceptance remains pending
Stage380 remains development-only
no third-party execution claim is made
no production-readiness claim is made
no pipeline-completion claim is made

These limitations are intentionally represented rather than hidden.

## License

This project is licensed under the MIT License.

See:

LICENSE

The MIT License applies to the published source code and documentation in this repository. It does not override restrictions, confidentiality requirements, third-party licenses, or security controls applicable to private material or external evidence.

---

## Stage386: PQC Independent Re-verification, Public Key Binding & Evidence Portability Gate

Stage386 extends Stage385 without replacing or rewriting the historical Stage385 state.

Stage385 identified a specific PQC verification gap:

- historical ML-DSA-65 signature execution evidence existed
- the current public repository did not contain the original ML-DSA-65 public key
- therefore a new third party could not independently repeat the cryptographic verification

Stage386 closes that gap by recovering the original Stage375 ML-DSA-65 public key, verifying its recorded identity, publishing only the public verification material, and independently re-verifying the historical Stage375 signature.

### Verified Stage386 Decision

Current Stage386 decision:

`pqc_independent_reverification_verified`

Verification status:

`verified`

The following bindings are verified:

- algorithm: `ML-DSA-65`
- public-key PEM SHA-256 match: `true`
- public-key DER SHA-256 match: `true`
- signature SHA-256 match: `true`
- signed-target SHA-256 match: `true`
- logical-attestation SHA-256 match: `true`
- Stage375 execution-receipt binding: `true`
- algorithm identifier verification: `true`
- context-string binding: `true`
- independent ML-DSA-65 signature verification: `true`
- third-party re-verification supported: `true`
- private key published: `false`

### Original Stage375 Public-Key Identity

The Stage386 public key is not a newly generated replacement key.

It is bound to the historical Stage375 ML-DSA-65 evidence.

Expected PEM SHA-256:

`1416f7cf4b7b755e86de50d56a63acb9d3b4cb2ce970253bccce45c26b358d19`

Expected DER SHA-256:

`2589f3e20ddcb0f6b0fec5a145d57d57c5ca8b93866a9672765d2e5557cae595`

Historical Stage375 Git commit:

`6d528f0a7fb48af18a1e6b78984b6ff5351236ba`

Historical Stage375 GitHub Actions run:

`29327350883`

Public key:

`docs/mldsa-production/stage375_mldsa65_public_key.pem`

### Independent Re-verification

Stage386 independently verifies the historical Stage375 ML-DSA-65 signature using only public verification material:

- ML-DSA-65 public key
- historical signature
- historical signed target
- Stage375 execution receipt
- Stage375 context string
- Stage386 verification policy

No ML-DSA private key is required.

No private seed is required.

No original Stage375 GitHub Actions runner is required.

### Cross-Environment Verification

Stage386 has been verified in more than one environment.

Local macOS verification:

- OpenSSL 3.6.3
- ML-DSA-65 public-key recognition: passed
- independent signature re-verification: passed
- deterministic Stage386 result: passed
- Fail-Closed test suite: passed

GitHub Actions Ubuntu verification:

- runner-default OpenSSL 3.0.13 did not provide the required ML-DSA-65 capability
- Stage386 correctly stopped instead of bypassing the requirement
- the workflow then adopted the Stage375-recorded OpenSSL source identity
- pinned OpenSSL version: 3.5.7
- source tag: `openssl-3.5.7`
- source commit:
  `8cf17aaeb4599f8af87fefd810b5b5fee90fe69e`
- independent ML-DSA-65 re-verification: passed

Verified Stage386 GitHub Actions run:

`31352161428`

Stage386 result SHA-256:

`aab6f8c3ac52ed142a7069de4aba09682ee5206904ff32519448f9548e723d9f`

### Fail-Closed Verification

Stage386 rejects or fails closed when required evidence or trust boundaries are violated.

Verified cases include:

- missing public key
- public-key PEM hash mismatch
- public-key DER hash mismatch
- missing signature
- signature tampering
- signed-target tampering
- Stage375 receipt-binding mismatch
- algorithm downgrade
- context-string mismatch
- private-key publication
- forbidden tracked private paths

The successful path is accepted only when all required bindings and the independent ML-DSA-65 verification succeed.

### Evidence Portability

Stage386 publishes a deterministic evidence-portability manifest so that third parties can identify the exact files required for re-verification and verify their SHA-256 identities.

Public Stage386 evidence is available under:

`docs/verification/stage386/`

Public evidence includes:

- `stage386_pqc_reverification_policy.json`
- `stage386_pqc_reverification_policy.sha256`
- `stage386_pqc_independent_reverification_result.json`
- `stage386_pqc_independent_reverification_result.sha256`
- `stage386_evidence_portability_manifest.json`
- `stage386_evidence_portability_manifest.sha256`

The original Stage375 ML-DSA-65 public key remains at:

`docs/mldsa-production/stage375_mldsa65_public_key.pem`

### Preservation Boundary

Stage386 does not rewrite the Stage385 historical record.

In particular, the Stage385 statement that the public ML-DSA key was unavailable at that stage remains part of the historical evidence.

Stage386 records the later transition in which the original Stage375 public key was recovered, identity-bound, published, and independently re-verified.

Stage386 does not modify, delete, replace, or overwrite the historical verification results of previous stages.

### Public and Private Boundaries

The following directories must remain private and must not be published to GitHub:

- `core/`
- `private_core/`
- `private/`
- `secrets/`
- `keys/`
- `imported/`

Stage386 must not publish:

- ML-DSA private keys
- ML-DSA private seeds
- KeyGen seed material
- GitHub Secrets
- credentials
- access tokens
- raw QKD secret-key material
- private cryptographic evidence

The ML-DSA-65 public key is public verification material and may be published.

### Important Limitation

Stage386 verifies the historical ML-DSA-65 signature and establishes independent PQC re-verification capability.

It does not prove that the entire QSP system is quantum safe.

Current limitation:

`entire_system_quantum_safe = false`

Stage386 also does not claim completion of Stage377 dual-timestamp final acceptance or system-wide formal acceptance.

## Stage386 License

This project is licensed under the MIT License.

See the repository-level:

`LICENSE`

The MIT License applies to the published source code and documentation in this repository. It does not override confidentiality requirements, security boundaries, private-material restrictions, or applicable third-party licenses.

## Stage387: PQC Multi-Implementation Interoperability & Verifier Independence Gate

Stage387 extends Stage386 without replacing or rewriting the historical Stage386 state.

Stage386 established independent ML-DSA-65 re-verification using the original Stage375 public key and public verification evidence.

Stage387 adds verifier independence by requiring the same historical ML-DSA-65 evidence to be accepted by more than one independent cryptographic implementation.

### Current Verified Decision

`pqc_multi_implementation_interoperability_verified`

### Verified Implementations

- OpenSSL ML-DSA-65 verification: verified
- Cloudflare CIRCL v1.6.5 ML-DSA-65 verification: verified
- Cross-implementation result match: true

Both implementations verify the same:

- Stage375 ML-DSA-65 public key
- Stage375 ML-DSA-65 signature
- Stage373 signed target
- ML-DSA context: `QSP-Stage375-v1`

No replacement key or replacement signature is generated.

### Public-Key and Evidence Binding

- Algorithm: `ML-DSA-65`
- Standard: `FIPS 204`
- Public-key PEM SHA-256 matches: true
- Public-key DER SHA-256 matches: true
- Raw public-key SHA-256 matches: true
- Signature SHA-256 matches: true
- Signed-target SHA-256 matches: true

### Fail-Closed Verification

Stage387 rejects or fails closed when required interoperability evidence or policy boundaries are violated.

Verified abnormal cases include:

- public key missing
- PEM public-key tampering
- signature tampering
- signed-target tampering
- raw public-key binding mismatch
- algorithm downgrade
- context mismatch
- FIPS binding mismatch
- source-stage mismatch
- secondary verifier mismatch
- CIRCL policy version mismatch
- CIRCL runtime version mismatch

### Evidence Portability

Stage387 provides a deterministic evidence portability manifest binding 15 verification artifacts, including:

- Stage387 policy
- Stage387 Python interoperability gate
- CIRCL ML-DSA-65 verifier
- Go module and dependency lock
- Fail-Closed test suite
- verified Stage387 result
- Stage375 public verification evidence
- deterministic manifest generator
- GitHub Actions interoperability workflow

The portability manifest is deterministically reproducible and SHA-256 bound.

### Verified GitHub Actions State

Stage387 has been independently verified on GitHub Actions / Ubuntu in addition to the local macOS environment.

Verified GitHub Actions run:

`31604092395`

Verified commit:

`248beb3f29b9df978f9a415a885972f0bd9ffc5f`

Workflow result:

`success`

### Security Boundary

Stage387 publishes only reviewed public verification material.

Stage387 does not publish:

- ML-DSA private keys
- private seeds
- KeyGen seeds
- credentials
- access tokens
- GitHub secrets
- private cryptographic material

The historical Stage375 ML-DSA-65 public key is public verification material and remains publishable.

### Important Limitation

Stage387 proves multi-implementation interoperability for the historical Stage375 ML-DSA-65 evidence.

It does not prove that the entire QSP system is quantum safe.

Current limitation:

`entire_system_quantum_safe = false`

Stage387 also does not claim completion of Stage377 dual-timestamp final acceptance or system-wide formal acceptance.

## Stage387 License

This project is licensed under the MIT License.

See the repository-level:

`LICENSE`

The MIT License applies to the published source code and documentation in this repository. It does not override confidentiality requirements, security boundaries, private-material restrictions, or applicable third-party licenses.

<!-- STAGE387_AUTHORITATIVE_REBIND_START -->
## Stage387 Authoritative PQC Multi-Implementation Interoperability Re-verification

Stage387 now contains an append-only authoritative re-verification lane that binds the final Stage386 authoritative evidence without rewriting the historical Stage387 record.

Current authoritative result:

- decision: `authoritative_pqc_multi_implementation_interoperability_verified`
- verification_status: `verified`
- algorithm: `ML-DSA-65` / FIPS 204
- OpenSSL verification: `true`
- Cloudflare CIRCL v1.6.5 verification: `true`
- cross-implementation result match: `true`
- authoritative checks: `28/28`
- failed checks: `0`
- critical failures: `0`
- fail-closed regression: `16/16`
- canonical restoration verified: `true`
- file mode restoration verified: `true`
- historical Stage387 record rewritten: `false`

Evidence hashes:

- authoritative result SHA-256: `e6bc2f2619159da19a499d5df53d7fa674feb99c21a19edc55ffc8f513667efb`
- fail-closed report SHA-256: `fee535829f38dca3bb6b5f62d85a8db680124c21591970fb8b78e82f49a6a532`
- authoritative package manifest SHA-256: `cec69e4c55b8b10c7bedee5b4cf3bf344fe269596c134c39fef065029e19b855`
- authoritative workflow SHA-256: `b5d9e234d03cab0a140f1fdf37a04a4526b094c8a325841a7905e182bd3d9bfa`

Public authoritative evidence:

- [Stage387 authoritative Stage386 binding](https://mokkunsuzuki-code.github.io/stage387/verification/stage387/authoritative-rebind/stage387_authoritative_stage386_binding_manifest.json)
- [Stage387 authoritative baseline](https://mokkunsuzuki-code.github.io/stage387/verification/stage387/authoritative-rebind/stage387_authoritative_interoperability_baseline.json)
- [Stage387 authoritative result](https://mokkunsuzuki-code.github.io/stage387/verification/stage387/authoritative-rebind/stage387_authoritative_interoperability_result.json)
- [Stage387 fail-closed report](https://mokkunsuzuki-code.github.io/stage387/verification/stage387/authoritative-rebind/stage387_authoritative_fail_closed_report.json)
- [Stage387 authoritative package manifest](https://mokkunsuzuki-code.github.io/stage387/verification/stage387/authoritative-rebind/stage387_authoritative_package_manifest.json)

Explicit non-guarantees:

- `entire_system_quantum_safe=false`
- `formal_acceptance_eligible=false`
- `formal_acceptance_issued=false`
- `formal_acceptance=false`
- `pipeline_completed=false`
- `public_release_allowed=false`
- `qkd_hardware_verified=false`
- `external_certification_completed=false`

Publishing verification evidence through GitHub Pages does not change these semantic non-guarantees.
<!-- STAGE387_AUTHORITATIVE_REBIND_END -->
