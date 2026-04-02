<?php
/**
 * Plugin Name: Auto Login for Sakura Rental Server
 * Description: Provides one-time, time-limited auto-login URLs using HMAC signatures.
 * Version: 1.0.3
 * Author: SAKURA internet Inc.
 * Requires at least: 5.0
 * Tested up to: 6.8
 * Requires PHP: 7.4
 * License: GPLv3 or later
 * License URI: https://www.gnu.org/licenses/gpl-3.0.html
 * Text Domain: auto-login-for-sakura-rental-server
 * Domain Path: /languages
 */

// WordPress 外から直接呼び出された場合は処理停止
if (!defined('ABSPATH')) {
    exit;
}

// 例外クラスを読み込み
require_once __DIR__ . '/includes/RequestException.php';

// 関数群を読み込み
require_once __DIR__ . '/includes/functions.php';

/**
 * WP-CLI コマンド：トークン発行
 * 使用例：
 *   wp auto-login-for-sakura-rental-server generate <user_id> [--expires=<seconds>] [--remote_addr=<ip>]
 */
if (defined('WP_CLI') && WP_CLI) {
  // CLIでの呼び出し
  require_once __DIR__ . '/includes/Sakura_Auto_Login_CLI.php';
  WP_CLI::add_command('auto-login-for-sakura-rental-server', 'Sakura_Auto_Login_CLI');
  return;
}

/**
 * 自動ログイン処理（init フック）
 * URLに ?rs_auto_login_token=<トークン> がある場合に実行
 */
add_action('init', function() {
    // phpcs:ignore WordPress.Security.NonceVerification.Recommended -- 外部システムからのGETトークン受理のためフォームNonce対象外
    $raw_token = filter_input(INPUT_GET, 'rs_auto_login_token', FILTER_DEFAULT);
    $token = is_string($raw_token) ? sanitize_text_field(wp_unslash($raw_token)) : '';

    $addr = filter_var($_SERVER['REMOTE_ADDR'] ?? '', FILTER_VALIDATE_IP);
    $addr = is_string($addr) ? $addr : '';
    $addr = sanitize_text_field($addr);
    sakura_auto_login_handle_request($token, $addr);
});
