# Stage385: Cryptographic Agility Inventory, PQC Migration Readiness & Algorithm Policy Enforcement Gate

日本語：

# 暗号アジリティ資産台帳・PQC移行準備性・アルゴリズムポリシー強制ゲート

Stage385は、Stage384までの検証履歴と公開構造を保持したまま、
QSPで確認できる暗号資産を証拠レベル付きで台帳化し、
PQC移行準備性と暗号アルゴリズムの状態をFail-Closedで判定するゲートです。

Stage385は、暗号方式の存在を推測しません。

公開ファイル、検証結果、実行Receipt、Sigstore Bundle、
Stage384の固定信頼状態など、確認できる証拠だけを使用します。

## Purpose

Stage385は、次の機能を追加します。

1. 暗号資産インベントリの固定
2. 暗号アルゴリズムと公開パラメータの識別
3. 古典公開鍵暗号のPQC移行対象判定
4. ML-DSA-65実行証拠の識別
5. 未検証・証拠不足暗号要素の明示
6. 禁止アルゴリズム検知
7. Stage384信頼状態へのSHA-256結合
8. Fail-Closedによる暗号ポリシー強制

Stage385は、秘密鍵の生成、秘密鍵のローテーション、
暗号方式の自動置換、正式承認、自動証明書発行を行いません。

## Current Verified State

現在のStage385判定は次のとおりです。

decision = cryptographic_inventory_incomplete
verification_status = verified_with_inventory_gaps_upstream_pending

asset_count = 10
migration_required_count = 2
inventory_incomplete_count = 4
prohibited_algorithm_count = 0

pqc_signature_execution_verified = true
hybrid_execution_evidence_present = true
current_public_mldsa_key_available = false
entire_system_quantum_safe = false

critical_failure_count = 0

これはStage385検証器の失敗ではありません。

暗号資産台帳と検証器は正常に検証されていますが、
現時点で4件の暗号関連項目に証拠不足または未完了状態が残っているため、
完全な暗号アジリティ合格状態へ昇格していないことを意味します。

## Cryptographic Inventory

現在の公開暗号資産台帳は10件です。

SHA-256
algorithm = SHA-256
status = allowed
confidence = verified_execution_evidence

Stage384を含む複数の検証・ハッシュ拘束で実際に使用されています。

Sigstore / Cosign Classical Signature
algorithm = ECDSA-P256
public key algorithm = id-ecPublicKey
curve = prime256v1 / P-256
message digest = SHA2_256
status = migration_required
migration_state = quantum_vulnerable
confidence = verified_execution_evidence

Stage374のSigstore Bundle内X.509証明書から実測した値です。

既存署名が無効という意味ではありません。
将来のPQC移行対象として分類しています。

Sigstore Certificate Signature
algorithm = ecdsa-with-SHA384
certificate public-key curve = P-256
status = migration_required
migration_state = quantum_vulnerable
confidence = verified_metadata
Rekor Transparency Binding
algorithm_identifier = Rekor-hashedrekord
status = allowed
confidence = verified_execution_evidence

Rekorは署名アルゴリズムではなく、
透明ログ結合として別分類しています。

ML-DSA-65
algorithm = ML-DSA-65
standard = FIPS 204
status = allowed
migration_state = pqc_primary
confidence = verified_execution_evidence
signature_verified = true

Stage375では、ML-DSA-65の実署名・実検証成功記録があります。

ただし、Stage375で参照された公開鍵ファイルは、
現在のStage385公開ツリーには存在しません。

そのため、

historical_execution_verification = true
current_standalone_public_reverification = false

として区別しています。

ML-DSA-65の存在だけで、
QSP全体が量子安全であるとは主張しません。

## Timestamp State
RFC3161
algorithm_identifier = RFC3161-SHA256
aggregate_stage377_rfc3161_verified = true
confidence = verified_metadata

Stage377集約結果ではRFC3161は検証済みです。

ただし現在リポジトリにある個別Receiptは初期の
not_executed状態であるため、
Stage385では独立再実行証拠ではなく
verified_metadataとして扱います。

OpenTimestamps
opentimestamps_verified = false
final_public_anchor_confirmed = false
status = evidence_required

OpenTimestampsは現時点では未完了です。

Stage377のverified proofとしてカウントしません。

## Revocation State
OCSP
status = not_provided
ocsp_verified = false
real_ocsp_verification_performed = false
CRL
status = not_provided
crl_verified = false
real_crl_verification_performed = false

Stage361にはOCSP・CRL証拠の受け皿がありますが、
実暗号検証はまだ成立していません。

## QKD State
evidence_classification = metadata_only
evidence_level = QKD-E1
qkd_metadata_bound = false

QKDは公開鍵署名アルゴリズムとは別カテゴリとして管理します。

QKD-E1メタデータを、
PQC移行完了やシステム全体の量子安全性の証拠として使用しません。

## Current Migration Gaps

現在のinventory incomplete対象は4件です。

stage361-crl-revocation
stage361-ocsp-revocation
stage377-opentimestamps
stage378-qkd-evidence

現在のPQC migration required対象は2件です。

stage374-sigstore-certificate-signature
stage374-sigstore-signature
## Decision Model

Stage385の判定優先順位は次です。

integrity or security boundary failure
↓
fail_closed

prohibited algorithm
↓
prohibited_algorithm_detected

unknown or evidence-required inventory remains
↓
cryptographic_inventory_incomplete

classical cryptography still requires migration
↓
pqc_migration_required

all requirements satisfied
↓
cryptographic_agility_profile_verified
## Stage384 Binding

Stage385はStage384の次の状態に結合されています。

decision = continuous_trust_state_verified_upstream_pending
verification_status = verified_unchanged_upstream_pending
change_detected = false
reverification_required = false
eligibility_invalidated = false
critical_failure_count = 0

Stage384の信頼状態が変化した場合、
Stage385はそのまま合格状態を維持しません。

## SHA-256 Evidence Chain

Stage385は次の4層をSHA-256で固定します。

Cryptographic Agility Policy
↓
Cryptographic Inventory
↓
PQC Migration Readiness Result
↓
Cryptographic Agility Manifest

現在の固定値：

policy_sha256 =
7a738eb462aed8daa77dc51c99305420bf1d074c45df330f2fd7106948cd371b

inventory_sha256 =
d9892b1e98b26abc9509320c6702c630048e1153e676336b0e5aef5cf2f9075f

embedded_result_sha256 =
124aaf947124c3012ccabb96ae64b17eb89b42e07e951774ebd9339bc605f3ca

result_file_sha256 =
ec60eb24222fe989bb9f358477456762512f75629d59bd068457644839d34db3

embedded_manifest_sha256 =
febb61606e0a772e9939462b767ab5f484824aa9d1043020c38fb92a740e0a9b

manifest_file_sha256 =
ceb517b385e06fbaa347af040db8a994537ba663b4079888e284344ab1faee4b
## Run Verification
python3 development/stage385/verify_stage385_cryptographic_agility.py

現在期待される判定：

cryptographic_inventory_incomplete
## Run Fail-Closed Tests
python3 development/stage385/test_stage385_fail_closed.py

現在のテスト：

10 tests
10 passed

確認対象には次が含まれます。

Policy SHA-256改ざん
Inventory SHA-256改ざん
duplicate asset_id
private-key publication claim
unsupported entire-system quantum-safe claim
Stage384 trust-state変更
検証証拠欠落
prohibited algorithm
inventory-gap判定
PQC migration requiredへの遷移

テストは一時コピー上で行われ、
実際のStage384およびStage385証拠を変更しません。

## Public Development Files
development/stage385/
├── README.md
├── stage385_cryptographic_agility_policy.json
├── stage385_cryptographic_agility_policy.sha256
├── stage385_cryptographic_inventory.json
├── stage385_cryptographic_inventory.sha256
├── verify_stage385_cryptographic_agility.py
├── test_stage385_fail_closed.py
├── stage385_pqc_migration_readiness_result.json
├── stage385_pqc_migration_readiness_result.sha256
├── stage385_cryptographic_agility_manifest.json
└── stage385_cryptographic_agility_manifest.sha256
## Formal-Acceptance Boundary

Stage385はdevelopment-onlyです。

formal_acceptance_eligible = false
formal_acceptance_issued = false
formal_acceptance = false
pipeline_completed = false
public_release_allowed = false

Stage385は、暗号アジリティとPQC移行準備性を判定しますが、
Stage377の未完了状態や上流正式承認状態を変更しません。

## Preservation Boundary

Stage385はStage377からStage384までの既存記録を
変更、削除、置換、上書きしません。

Stage384のTrust-State Baseline、
Change Detection Result、
Continuous Verification Manifestも変更しません。

## Security and Publication Boundary

次のディレクトリは公開対象にしません。

core/
private_core/
private/
secrets/
keys/
imported/

次の情報も公開しません。

private keys
key seeds
credentials
access tokens
raw QKD secret material
raw RFC3161 proof binary
raw OpenTimestamps proof binary
non-public core material

公開するのは、レビューされた公開ソースコード、
暗号アルゴリズムメタデータ、
安全な公開パラメータ、
検証結果、
SHA-256記録だけです。

## Limitations

Stage385は、現在確認できる証拠を分類するゲートです。

次のことは主張しません。

QSP全体が量子安全である
PQC移行が完了している
OpenTimestamps最終確定が完了している
OCSP検証が完了している
CRL検証が完了している
QKD実機証拠が完成している
Stage377以降のFormal Acceptanceが成立している
## License

Stage385の公開ソースコードと文書は、MIT Licenseで提供します。

完全なライセンス本文は、
リポジトリ直下のLICENSEを参照してください。

MIT Licenseは、秘密情報の非公開条件、
セキュリティ境界、
第三者ライセンス、
非公開コアの制限を無効にするものではありません。
