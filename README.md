# セサミロック制御Webアプリ

これは、Replitを使用してSesameスマートロックを制御するためのシンプルなWebアプリケーションです。セサミロックを開く、閉じる、オートロック機能を解除することができます。

## 前提条件

- セサミスマートロック
- Replitアカウント
- IFTTTアカウント（オートアンロック機能用）

## 設定

1. このリポジトリをReplitアカウントにクローンします。または、以下のリンクからフォークしてください。
   [https://replit.com/@yuki36/SesameUI?v=1](https://replit.com/@yuki36/SesameUI?v=1)

2. Replitプロジェクトで以下の環境変数を設定します。

   - `uuid`: セサミロックのUUID
   - `secret_key`: セサミロックのシークレットキー
   - `api_key`: セサミAPIキー
   - `ifttt`: オートアンロック機能用のIFTTT URL
   - `password`: ロック制御Webアプリを保護するためのパスワード

   UUIDとシークレットキーは、セサミアプリのロック設定で見つけることができます。APIキーは、セサミのウェブサイトで開発者アカウントに登録することで取得できます。

3. オートアンロック機能用のIFTTTアプレットを作成します。

   - トリガーとして「Webhooks」サービスを持つ新しいアプレットを設定します。
   - トリガーイベントとして「ウェブリクエストを受信する」を選択します。
   - イベント名を「autounlock」と設定します。
   - アクションとして「通知」サービスを選択します。
   - 通知テキストを「おめでとうございます！あなたのセサミロックが解除されました。」に設定します。

4. Replitで「Run」ボタンをクリックしてWebアプリをデプロイします。

5. 提供されたURLを使用してWebアプリにアクセスします。

## 使い方

1. Webアプリをブラウザで開きます。

2. 環境変数で設定したパスワードを入力します。

3. 「開く」ボタンをクリックしてロックを開くか、「閉じる」ボタンをクリックしてロックを閉じます。

4. オートロック機能を解除するには、「オートロック解除」ボタンをクリックします。これにより、IFTTTにリクエストが送信され、その後、携帯電話に通知が送信されます。通知を確認してオートロック機能を解除します。

## トラブルシューティング

問題が発生した場合は、以下を確認してください。

- すべての環境変数が正しく設定されていることを確認してください。
- セサミロックがインターネットに接続されており、安定した接続があることを確認してください。
- IFTTTアプレットが正しく設定されており、イベント名がWebアプリのものと一致していることを確認してください。

それでも問題が解決しない場合は、Replitコンソールでエラーメッセージやログを確認してください。