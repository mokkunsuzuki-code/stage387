# Stage387: PQC Multi-Implementation Interoperability & Verifier Independence Gate

Stage387 extends Stage386 without replacing or rewriting the historical Stage386 state.

## Purpose

Stage387 verifies that the historical Stage375 ML-DSA-65 signature can be independently verified by more than one implementation.

Stage386 established independent re-verification using OpenSSL.

Stage387 adds an independent second implementation:

- OpenSSL
- Cloudflare CIRCL

The same historical evidence is used by both implementations.

No new ML-DSA key is generated.

No new ML-DSA signature is generated.

## Historical Evidence

Algorithm:

ML-DSA-65

Context string:

QSP-Stage375-v1

Public-key PEM SHA-256:

1416f7cf4b7b755e86de50d56a63acb9d3b4cb2ce970253bccce45c26b358d19

Public-key DER SHA-256:

2589f3e20ddcb0f6b0fec5a145d57d57c5ca8b93866a9672765d2e5557cae595

Raw ML-DSA-65 public-key SHA-256:

d9ebcddf52e54584ffde5db4d3921274cbeff9082387d9c78bbbefe999dd7086

Signature SHA-256:

6cc2d3d0a3a7d5a603346dc65597aac950dc97cbbaeddfecd6405c7d585445c4

Signed-target SHA-256:

6ecf58d0070d8db920744b7d32331e01e8e1aef2eded02dde428b80def79d5e6

## Verified Implementations

### OpenSSL

The historical Stage375 ML-DSA-65 signature is independently verified with OpenSSL.

### Cloudflare CIRCL

Pinned implementation:

Cloudflare CIRCL v1.6.5

The same historical Stage375 ML-DSA-65 signature was independently verified with CIRCL.

Observed local verification state:

- CIRCL public key decoded: true
- CIRCL ML-DSA-65 verification: true
- CIRCL verification exit code: 0
- Go test exit code: 0

## Interoperability Model

Stage387 requires both implementations to verify the same:

- algorithm
- public key
- signature
- signed target
- context string

A success decision must not be emitted if only one implementation verifies the evidence.

## Target Decision

Successful decision:

pqc_multi_implementation_interoperability_verified

## Fail-Closed Conditions

Stage387 must reject or fail closed when:

- the public key is missing
- the public-key identity changes
- the raw public-key binding changes
- the signature is missing
- the signature changes
- the signed target changes
- the context changes
- the algorithm changes
- OpenSSL verification fails
- CIRCL verification fails
- implementation results disagree
- private-key material is published
- forbidden private paths are tracked

## Security Boundary

Stage387 publishes only public verification evidence.

Stage387 must never publish:

- ML-DSA private keys
- ML-DSA private seeds
- KeyGen seeds
- GitHub secrets
- credentials
- access tokens
- private cryptographic material

## Important Limitation

Successful Stage387 verification means that the historical Stage375 ML-DSA-65 signature is independently verifiable by multiple implementations.

It does not mean that the entire QSP system is quantum safe.

It does not mean that Stage377 dual-timestamp final acceptance is complete.

It does not mean that system-wide formal acceptance is complete.

## License

MIT License.
