# Stage384: Continuous Trust-State Reverification & Change Invalidation Gate

日本語：

# 継続的信頼状態再検証・変更失効判定ゲート

Stage384は、Stage383までの検証履歴と公開ページ構造を保持したまま、
信頼状態を継続的に再検証し、変更の影響を判定するゲートです。

## Purpose

Stage384は、次の機能を追加します。

1. Stage383の信頼状態を決定論的な基準として固定する
2. 監視対象ファイルのSHA-256とサイズを再計算する
3. 基準状態からの変更を検知する
4. 変更をmaterialまたはcriticalとして分類する
5. 必要に応じて再検証要求または適格性無効化を行う

Stage384は正式承認や証明書を自動発行しません。

## Continuous Verification

Continuousは、無停止のリアルタイム監視を意味しません。

次の実行方法による、ポリシーで定義された継続的な再検証を意味します。

- 定期実行
- Pushを契機とした実行
- 手動実行
- 上流証拠更新後の実行

## Current State

現在のStage384判定は次のとおりです。

```text
decision = continuous_trust_state_verified_upstream_pending
verification_status = verified_unchanged_upstream_pending
change_detected = false
detected_change_count = 0
material_change_count = 0
critical_change_count = 0
reverification_required = false
eligibility_invalidated = false
critical_failure_count = 0
```

これは、Stage377の完了を待ちながら、Stage383までの監視対象に
新しい変更や不整合がないことを確認した状態です。

## Stage383 Recovery Session

Stage384は、次の決定論的Stage383セッションに結合されています。

```text
stage383-66bce0a526782ef0e49221e70bcc939268f0d04e6e2e86e34aea9aed6caf5505
```

セッションIDが変化した場合は、critical変更として扱います。

## Change Decisions

変更なし：

```text
continuous_trust_state_verified_upstream_pending
```

再検証が必要な変更：

```text
trust_state_change_reverification_required
```

適格性を無効化する重大変更：

```text
formal_acceptance_eligibility_invalidated
```

整合性検証の失敗：

```text
fail_closed
```

## Run Verification

```bash
python3 development/stage384/verify_stage384_continuous_trust_state.py
```

## Run Fail-Closed Tests

```bash
python3 development/stage384/test_stage384_fail_closed.py
```

現在のテストは10件で、変更なし、監視対象欠落、Workflow変更、
ポリシー改変、SHA-256改ざん、Stage383セッション不一致などを確認します。

テストは一時コピー上で実行され、実際のStage377からStage384の
証拠ファイルを変更しません。

## Public Development Files

```text
development/stage384/
├── README.md
├── stage384_continuous_verification_policy.json
├── stage384_continuous_verification_policy.sha256
├── stage384_trust_state_baseline.json
├── stage384_trust_state_baseline.sha256
├── verify_stage384_continuous_trust_state.py
├── test_stage384_fail_closed.py
├── stage384_change_detection_result.json
├── stage384_change_detection_result.sha256
├── stage384_continuous_verification_manifest.json
└── stage384_continuous_verification_manifest.sha256
```

## Preservation Boundary

Stage384は、Stage377からStage383の記録を変更・上書きしません。

Stage384が行うのは、観測、ハッシュ計算、比較、変更分類、
再検証要求および適格性無効化判定です。

## Formal-Acceptance Boundary

Stage384はdevelopment-onlyです。

```text
formal_acceptance_eligible = false
formal_acceptance_issued = false
formal_acceptance = false
pipeline_completed = false
public_release_allowed = false
issuance_transition_allowed = false
```

Stage384は証明書を発行せず、上流の正式承認状態を独自に昇格させません。

## Security and Publication Boundary

次のディレクトリは公開しません。

```text
core/
private_core/
private/
secrets/
keys/
imported/
```

秘密鍵、認証情報、トークン、QKD秘密鍵素材、
生のタイムスタンプ証明バイナリ、非公開コアも公開しません。

公開するのは、確認済みのポリシー、公開ソースコード、
安全なメタデータ、SHA-256記録、検証結果だけです。

## License

Stage384の公開ソースコードと文書は、MIT Licenseで提供します。

完全なライセンス本文は、リポジトリ直下の`LICENSE`を参照してください。

MIT Licenseは、秘密情報の非公開条件、セキュリティ境界、
第三者ライセンス、非公開コアの制限を無効にするものではありません。
