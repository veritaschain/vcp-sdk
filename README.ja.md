# VCP SDK — VeritasChain Protocol v1.2 のオフライン・コア

[English](README.md)

**バージョン 0.1.0(プレリリース)。** [VeritasChain Protocol(VCP)v1.2](https://github.com/veritaschain/vcp-spec/tree/v1.2.0/spec/v1.2)
のイベントをオフラインで作成・検証するための、Python・TypeScript・MQL5 のライブラリです。
正規化してのハッシュ計算、Merkle 木、Ed25519 署名、三値の結果を返す検証を扱います。

> **位置づけと開示**
>
> * **当事者による実装です。** VeritasChain Standards Organization(VSO)を運営する
>   VeritasChain株式会社が作成したもので、外部の実装でも独立した実装でもありません。
>   VSO が開示している外部実装の数(ゼロ)は変わりません。
> * **認証を受けていません。適合の主張でもありません。** 検証器の `VALID` は、実行した検査が
>   一致したことを示すだけで、イベントを作成したシステムが VCP や VAP に適合していることは示しません。
> * **プレリリースです。** 1.0 までに API が変わることがあります。VCP v1.2 の記述が
>   曖昧な箇所では SDK が解釈を選んでいます。[INTERPRETATIONS.md](INTERPRETATIONS.md) に、
>   その解釈と SDK 独自の検証上の判断を、把握しているかぎりすべて挙げています。
>   他の実装とハッシュを突き合わせる前に読んでください。
> * **このリポジトリからのみインストールしてください。** VSO はこれらのパッケージを PyPI・npm に公開していません。

## できること

| | Python | TypeScript | MQL5 |
|---|---|---|---|
| 正規化 JSON(RFC 8785、整数は正確な桁。INTERPRETATIONS.md I-4) | ✓ | ✓ | ✓(浮動小数点数なし) |
| EventHash(SHA-256。Python・TS は SHA3-256、BLAKE3 も) | ✓ | ✓ | SHA-256 |
| RFC 6962 Merkle 根、包含証明、一貫性証明 | ✓ | ✓ | 根、包含証明の検証 |
| イベントと根の Ed25519 署名 | ✓ | ✓ | —(`vcp seal` で署名) |
| イベント・バッチ・AnchorRecord の作成 | ✓ | ✓ | 未署名イベント(JSON Lines) |
| 三値の検証器(イベント、バッチ、連鎖、包含) | ✓ | ✓ | — |
| コマンドライン(`vcp`) | ✓ | — | — |

検証は検査ごとに次のいずれかを返します。

| 結果 | 意味 |
|---|---|
| `VALID` | 検査を実行し、一致した。 |
| `INVALID` | 検査を実行し、不一致または不正な形式を示した。 |
| `INDETERMINATE` | 与えられた材料では検査を実行できなかった(信頼できる鍵がない、外部アンカーの証明や検証手段がない、未対応のアルゴリズムなど)。**合格ではありません。** |

検査結果は INVALID > INDETERMINATE > VALID の優先順位でまとめます。VSO の
[三値化の議論用草案](https://github.com/veritaschain/vap-spec/blob/main/proposals/three-valued-verification/README.md)(未採択)に沿っています。
SDK が実行しない検査を VALID と報告することはありません。INDETERMINATE とするか、
レポートの注記で「検査していない」と明記します。形式だけを見る検査は、名前でそう示します
(`anchor_timestamp_format`)。

## できないこと

* どこにも接続しません。外部アンカー(OpenTimestamps、RFC 3161 TSA、ブロックチェーン、
  第三者の証明を受けたデータベース)は呼び出し側が行います。VCP v1.2 §6.3.3 はすべての
  ティアで外部アンカーを求めています。アンカーを検証するには `external_anchor_verifier`
  を渡します。渡さなければ結果は `INDETERMINATE` です。
* 鍵がイベントに書かれた当事者のものであることは確かめません。信頼する鍵は呼び出し側が与えます。
* 記録された内容が真実であること、記録されるべきイベントがすべて記録されたこと、取引や
  AI の判断が正しかったことは示しません。網羅性は、アンカーされた根との関係で、アンカー粒度でのみ確かめます。
* 事後の検証です。取引や AI の動作を止めたり、遮ったり、変えたりはしません。
* COSE/SCITT のエンベロープの読み取り、ECDSA・RSA・耐量子署名の検証、`Security.AnchorReference`
  の検査、JSON Schema による完全な検証は行いません。
* [vcp-sdk-spec](https://github.com/veritaschain/vcp-sdk-spec) の実装ではありません。
  同仕様は VCP v1.1 と VeritasChain Cloud/Explorer API のクライアントを対象にしています。

## VCP v1.2 の例示コードとの主な違い

* **Merkle 木は RFC 6962 に従います。** VCP v1.2 §6.2.1 は RFC 6962 への準拠を求めていますが、
  その例示コードは奇数ノードを複製します。木のサイズが2のべき乗でない場合、根は必ず異なります。
  例示コードの方式で作られたバッチは、INVALID ではなく `INDETERMINATE`(`LEGACY_MERKLE_CONSTRUCTION`)
  と報告します。INTERPRETATIONS.md I-1 を参照してください。
* **整数は正確な桁でハッシュします。** RFC 8785 は数値を binary64 として扱うため、ナノ秒の
  `TimestampInt` の多くは丸められるか、別の桁で書かれます。SDK はすべての整数を正確に書くので、
  異なる整数が同じハッシュになることはありません。2^53 を超える整数に RFC 8785 を当てはめる
  実装とは、そうしたイベントのハッシュが異なります。I-4 を参照してください。
* **署名の対象は狭い範囲です。** AnchorRecord の署名は根だけを対象とするため、`EventCount`、
  `FirstEventID`、`LastEventID`、`PolicyID` は署名ではなく、与えられたイベントと照合します。I-6 を参照してください。

## インストール

Python 3.10 以上:

```bash
pip install "git+https://github.com/veritaschain/vcp-sdk.git@v0.1.0#subdirectory=python"
```

TypeScript(Node 20 以上、またはブラウザ向けバンドラ):

```bash
git clone --branch v0.1.0 https://github.com/veritaschain/vcp-sdk.git
cd vcp-sdk/typescript && npm ci && npm run build
# 利用側のプロジェクトで:  npm install /path/to/vcp-sdk/typescript
```

MQL5:`mql5/Include/VeritasChain` を `MQL5/Include/` に、必要なスクリプトとエキスパートを
`MQL5/Scripts/`・`MQL5/Experts/` にコピーします。[mql5/README.md](mql5/README.md) を参照してください。

## 使い方

Python と TypeScript のコード例は [README.md](README.md) の Quick start にあります(コードは共通です)。

コマンドラインの終了コードは、0 が VALID(または成功)、1 が INVALID、2 が INDETERMINATE、
3 が使い方の誤り・読めないか不正な入力・`vcp seal` による署名の拒否です。検証器の内部で
予期しないエラーが起きた場合は INDETERMINATE の検査(`VERIFIER_ERROR`)として報告するので、
終了コードは 2(他に INVALID の検査があれば 1)です。

秘密鍵はファイルか環境変数 `VCP_PRIVATE_KEY` から読み、コマンドラインの引数では受け取りません。
POSIX 系の OS では鍵ファイルの権限が 0600 でなければなりません。Windows では ACL を確認しないので、
ファイルへのアクセスは利用者が制限してください。環境変数は、そのシェルから起動したすべてのプロセスに引き継がれます。

```bash
vcp keygen --out ea.key                       # シードを権限 0600 で書き、公開鍵を表示
vcp verify-batch events.jsonl --anchor anchor.json --public-key <base64>
vcp verify-chain events.jsonl
vcp seal unsigned.jsonl --private-key-file ea.key --out events.jsonl --anchor-out anchor.json
```

`vcp seal` は署名の前に各行を検査します(構造、タイムスタンプ、作成側が書いた EventHash、
各行の PrevHash のつながり)。1行でも不合格なら署名しません。一方、正しい行はファイルにあるかぎり
すべて署名するため、作成側が書き込むフォルダは保護してください。連鎖が複数のファイルに分かれる場合は、
前のファイルを `vcp seal` したときに表示される `last_event_hash` を `--prior-hash` に渡します。
1行目がそれにつながっていなければ署名しません。

TypeScript では、イベントの JSON を `JSON.parse` ではなく `parseJson`・`parseJsonLines` で読んでください。
`JSON.parse` はナノ秒のタイムスタンプを丸めます。書き出しには `toJson` を使います。
TypeScript の `nowNs()` の分解能は1ミリ秒です。それより細かい時刻が必要なら `timestampNs` を渡してください。

## 検証の方法

| 対象 | 根拠 |
|---|---|
| RFC 8785 | RFC 8785 Appendix B の数値と §3.2 の例。ランダムな3,000文書を Python の [`rfc8785`](https://pypi.org/project/rfc8785/) パッケージと照合。4,500個の数値を V8 の `Number#toString` と照合。2^60、−2^63、異なるハッシュになるべき組(1791504000123456768 と …800)を含む整数のベクタ |
| Merkle | Certificate Transparency の参照用の根。サイズ1〜64で、根・包含証明・一貫性証明が [transparency-dev/merkle](https://github.com/transparency-dev/merkle) と一致(`tools/merkle-crosscheck-go`)。改変を加えた入力でのテスト |
| Ed25519 | RFC 8032 §7.1 の TEST 1〜3。小位数の8種の鍵の符号化、非正規の符号化、ねじれ(torsion)成分を含む鍵、単位元の鍵による偽造、R に小位数の成分を含む署名、S + L の署名を、両言語で拒否することを確認 |
| 不正な入力 | `test-vectors/hostile.json`:誤った型、組み込みプロパティ名と同じフィールド、巨大な値や深い入れ子、行区切り文字を使った細工、不正なタイムスタンプやアンカー、改ざんしたイベントと各種の不正な AnchorRecord フィールドの組み合わせなど、114件の不正・敵対的な入力。期待する結果は手で書いており、両方のテストがそのすべてを再現し、例外を出さないことを確認 |
| 言語間 | Python と TypeScript が互いの正規化バイト列・ハッシュ・署名をバイト単位で再現(`test-vectors/vectors.json`)。binary64 で正確に表せるタイムスタンプを含め、互いが作ったバッチを相互に検証(`tools/crosslang/run.sh`)。両方のベクタファイルの検証ケースすべてで、TypeScript のレポートが Python のレポートと同じ検査を、同じ順序・同じ結果・同じ理由で並べることを確認 |
| MQL5 | `tools/mql5/compile-and-selftest.sh` が Wine 上の MetaEditor でコンパイルし、MetaTrader 5 の端末で自己テストを実行します(CI の `mql5` ワークフローがこれを実行)。2026-10-25 に MetaTrader 5 build 6283・Wine 11.20 で、自己テストと例示 EA はエラー0・警告0、自己テストは 199 件合格・0 件失敗。Windows とログインした口座では試していません。例示 EA はコンパイルのみで、動かしてはいません。同じベクタから生成した `mql5/Scripts/VeritasChain/VCP_SelfTest.mq5` が、正規化の出力、ハッシュ、Merkle の根と証明、書き込み(行形式、EventHash というキーを含む Payload がある場合の再開、別の連鎖と不完全な最終行の拒否、新しいファイルでの連鎖の継続)を確かめます。使う前にお使いの端末で実行してください。 |

`vectors.json` のバッチと連鎖の12ケースは、期待する結果を Python の検証器から得ており、正しい入力だけを扱います。
不正な入力のコーパスの期待する結果は手で書いたもので、どちらの実装からも得ていません。

テストの実行:

```bash
cd python && pip install -e ".[test]" && pytest
cd typescript && npm ci && npm test
tools/crosslang/run.sh
```

## リポジトリの構成

```
python/        Python パッケージ veritaschain-vcp(import veritaschain_vcp)、CLI `vcp`
typescript/    TypeScript パッケージ @veritaschain/vcp
mql5/          VCP.mqh、自己テスト用スクリプト、EA の例
test-vectors/  3言語が共有する vectors.json(正しい入力)と hostile.json(敵対的な入力)
tools/         ベクタの生成、Ed25519 の境界例、Go による Merkle の照合、言語間の確認
INTERPRETATIONS.md   VCP v1.2 が曖昧な箇所での解釈と、SDK 独自の検証上の判断
```

## ライセンスと連絡先

Apache License 2.0([LICENSE](LICENSE)、[NOTICE](NOTICE))。
仕様に関する問い合わせ:standards@veritaschain.org。脆弱性の報告:[SECURITY.md](SECURITY.md)。
