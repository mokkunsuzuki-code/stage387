# Stage386: PQC Independent Re-verification, Public Key Binding & Evidence Portability Gate

Stage386 extends Stage385 by closing the ML-DSA-65 independent verification gap identified by the cryptographic agility inventory.

## Purpose

Stage386 establishes that the historical Stage375 ML-DSA-65 verification can be independently reproduced without access to the ML-DSA private key or the original GitHub Actions execution environment.

Stage386 verifies:

- the original Stage375 ML-DSA-65 public key
- the public-key PEM SHA-256 binding
- the canonical DER SHA-256 binding
- the historical signature SHA-256 binding
- the original signed-target SHA-256 binding
- the Stage375 context-string binding
- independent ML-DSA-65 signature verification
- evidence portability for third-party verification

## Original Stage375 Evidence

Algorithm:

ML-DSA-65

FIPS standard:

FIPS 204

Context string:

QSP-Stage375-v1

Expected public-key PEM SHA-256:

1416f7cf4b7b755e86de50d56a63acb9d3b4cb2ce970253bccce45c26b358d19

Expected public-key DER SHA-256:

2589f3e20ddcb0f6b0fec5a145d57d57c5ca8b93866a9672765d2e5557cae595

Expected signature SHA-256:

6cc2d3d0a3a7d5a603346dc65597aac950dc97cbbaeddfecd6405c7d585445c4

Expected signed-target SHA-256:

6ecf58d0070d8db920744b7d32331e01e8e1aef2eded02dde428b80def79d5e6

Expected logical attestation SHA-256:

d54b7524ced420f664da9d370985585d649ce80584b64bdf87342f89dbfde89f

Historical Stage375 GitHub SHA:

6d528f0a7fb48af18a1e6b78984b6ff5351236ba

Historical Stage375 GitHub Actions run:

29327350883

## Public Evidence

The following public verification material is used:

- docs/mldsa-production/stage375_mldsa65_public_key.pem
- docs/mldsa-production/stage375_mldsa65_signature.bin
- docs/mldsa-production/stage375_mldsa65_execution_receipt.json
- docs/final-acceptance-attestation/stage373_final_acceptance_attestation.json

## Security Boundary

Stage386 publishes only public verification material.

Stage386 must never publish:

- ML-DSA private keys
- ML-DSA private seeds
- KeyGen seed material
- GitHub Actions secrets
- credentials
- access tokens
- private cryptographic material

The Stage375 private key remains outside the public verification boundary.

## Decision Model

Stage386 succeeds only when all required bindings and the independent ML-DSA-65 signature verification succeed.

Successful decision:

pqc_independent_reverification_verified

Fail-closed or incomplete states include:

- pqc_public_key_missing
- pqc_public_key_pem_hash_mismatch
- pqc_public_key_der_hash_mismatch
- pqc_signature_hash_mismatch
- pqc_signed_target_hash_mismatch
- pqc_logical_attestation_hash_mismatch
- pqc_independent_reverification_failed
- fail_closed

## Important Limitation

Successful Stage386 verification means that the historical Stage375 ML-DSA-65 signature can be independently reverified.

It does not mean that the entire QSP system is quantum safe.

## License

MIT License.
