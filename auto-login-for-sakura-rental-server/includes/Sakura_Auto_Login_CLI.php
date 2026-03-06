<?php
 /**
  * WP-CLI コマンド: WP Auto Login for Sakura Rental Server
  *
  * このクラスは `wp auto-login-for-sakura-rental-server` コマンドを提供します。
  *
  */
class Sakura_Auto_Login_CLI {
    /**
     * 自動ログイントークンを生成し、URL を出力する
     *
     * @param string[] $args       CLI 引数（user_id）
     * @param array{
     *     expires?: string,      // 有効期限（秒）。省略時は300
     *     remote_addr?: string,  // 発行者のIPアドレス。
     *     username?: string      // RSのユーザー名。アカウントの場合は空
     * } $options CLI のオプション引数
     * @return void
     */
    public function generate($args, $options) {
        $user_id = $args[0] ?? '';
        if ($user_id === '') {
            WP_CLI::error('user_id is required.');
        }

        $expires = isset($options['expires']) ? intval($options['expires']) : 300;
        if ($expires <= 0) {
            WP_CLI::error('--expires must be a positive integer.');
        }

        $addr = $options['remote_addr'] ?? '';
        $username = $options['username'] ?? '';

        try {
            $token = sakura_auto_login_generate_token($user_id, $expires, $addr, $username);
            WP_CLI::line(site_url("?rs_auto_login_token={$token}"));
        } catch (\Throwable $e) {
            WP_CLI::error('failed to generate token. Reason: ' . $e->getMessage());
        }
    }
}
