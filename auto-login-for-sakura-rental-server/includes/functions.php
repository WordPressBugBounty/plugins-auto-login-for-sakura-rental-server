<?php

// トークン保存用のオプションキー
define('SAKURA_AUTO_LOGIN_TOKENS_OPTION', 'sakura_auto_login_tokens');

/**
 * 自動ログイン用の HMAC トークンを生成
 *
 * @param  string     $user_id     WordPress ユーザーID
 * @param  int        $expires     有効期限（秒）
 * @param  string     $addr        発行者IP
 * @param  string     $username    RSのユーザー名
 * @return string     $token
 * @throws RequestException        ユーザーが存在しない
 */
function sakura_auto_login_generate_token(string $user_id, int $expires, string $addr, string $username): string {
    // ユーザーの存在を確認
    $user = get_user_by('id', $user_id);
    if (!$user) {
        throw new RequestException('user not found');
    }

    // 有効期限と署名ペイロード生成
    $expires_at = time() + $expires;
    $token = sakura_auto_login_expected_signature($user_id, $expires_at);

    // トークンを追加
    sakura_auto_login_add_token([
        'token'      => $token,
        'userID'    => $user_id,
        'expiresAt' => $expires_at,
    ]);

    // NOTE: オブジェクトキャッシュ有効時、別リクエストでもキャッシュが残る場合がある
    wp_cache_delete($user_id, 'user_meta');

    // ユーザー発行履歴の取得と初期化
    $history = get_user_meta($user_id, 'sakura_auto_login_history', true);
    if (!is_array($history)) {
        $history = [];
    }

    // 新しい履歴を追加
    $history[] = [
        'token'      => $token,
        'status'     => 'issued',
        'expiresAt'  => $expires_at,
        'issuedAt'   => time(),
        'usedAt'     => null,
        'issuedBy'   => $addr,
        'usedBy'     => null,
        'issuedUser' => $username,
    ];
    // 古い履歴は最大100件に制限
    $history = array_slice($history, -100);

    update_user_meta($user_id, 'sakura_auto_login_history', $history);

    return $token;
}

/**
 * トークンの署名・期限・存在確認を行う
 *
 * @param  string $token 64文字の HMAC トークン
 * @return string $user_id 検証に成功したユーザーID
 * @throws RequestException トークンが存在しない/期限切れ/署名不正/ユーザー不在など
 */
function sakura_auto_login_verify_token(string $token): string {
    // トークン形式チェック
    if (strlen($token) !== 64 || !ctype_xdigit($token)) {
        throw new RequestException('invalid token', 403);
    }

    // トークン情報を取得（存在チェック）
    $item = sakura_auto_login_find_token($token);
    if (!$item || empty($item['userID']) || empty($item['expiresAt'])) {
        throw new RequestException('token not found or expired', 403);
    }

    $user_id = $item['userID'];

    // 対象ユーザーの存在を確認
    $user = get_user_by('id', $user_id);
    if (!$user) {
        throw new RequestException('user not found', 403);
    }

    $expires_at = (int)$item['expiresAt'];

    // HMAC署名の再計算と照合
    $expected = sakura_auto_login_expected_signature($user_id, $expires_at);
    if (!hash_equals($expected, $token)) {
        throw new RequestException('invalid signature', 403);
    }

    return $user_id;
}

/**
 * 検証済みトークンを消費（削除＆履歴「used」に更新）
 *
 * @param  string $token 64文字の HMAC トークン
 * @param  string $user_id 検証に成功したユーザーID
 * @param  string $addr リクエスト元のIPアドレス。空なら 'system'
 * @return void
 */
function sakura_auto_login_consume_token(string $token, string $user_id, string $addr): void {
    // NOTE: オブジェクトキャッシュ有効時、別リクエストでもキャッシュが残る場合がある
    wp_cache_delete($user_id, 'user_meta');

    // トークンを削除して無効化（ワンタイム）
    sakura_auto_login_delete_token($token);

    // トークン使用済みに履歴更新
    $history = get_user_meta($user_id, 'sakura_auto_login_history', true);
    if (!is_array($history)) {
        $history = [];
    }

    foreach ($history as &$item) {
        if (!is_array($item)) {
            continue;
        }
        // トークンが一致していて、未使用の場合
        if (($item['token'] ?? '') === $token && ($item['status'] ?? '') === 'issued') {
            $item['status'] = 'used';
            $item['usedAt'] = time();
            $item['usedBy'] = $addr ?? 'system';
            break;
        }
    }
    update_user_meta($user_id, 'sakura_auto_login_history', $history);
}

/**
 * init フックに登録された自動ログイン処理関数
 * 
 * @param string $token 64文字の HMAC トークン
 * @param string $addr リクエスト元のIPアドレス
 * @return void
 */
function sakura_auto_login_handle_request(string $token, string $addr): void {
    if (empty($token)) {
        return;
    }

    if (empty($addr) || false === filter_var($addr, FILTER_VALIDATE_IP)) {
        wp_die(esc_html__('invalid remote address', 'auto-login-for-sakura-rental-server'), '', ['response' => 403]);
    }

    // IPベースの1秒レート制限（不正アクセス防止）
    $rate_key = "sakura_auto_login_challenge_{$addr}";
    if (get_transient($rate_key)) {
        wp_die(esc_html__('rate limit exceeded', 'auto-login-for-sakura-rental-server'), '', ['response' => 429]);
    }
    set_transient($rate_key, 1, 1);

    // トークン検証
    $token = sanitize_text_field($token);

    try {
        $user_id = sakura_auto_login_verify_token($token);
        sakura_auto_login_consume_token($token, $user_id, $addr);
        wp_set_auth_cookie($user_id);
        wp_redirect(admin_url());
        exit;
    } catch (RequestException $e) {
        $code = $e->getCode() ?: 403;

        /* translators: %s: reason message */
        $text = __('invalid or expired token. Reason: %s', 'auto-login-for-sakura-rental-server');
        $msg  = sprintf($text, $e->getMessage());

        // ステータスコードは整数に正規化（4xx/5xx 以外は 403）
        $status = (int) $code;
        if ($status < 400 || $status > 599) {
            $status = 403;
        }

        // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped -- 'response' は数値で画面出力ではないため
        wp_die(esc_html($msg), '', ['response' => $status]);
    } catch (\Throwable $e) {
        wp_die(esc_html__('internal server error', 'auto-login-for-sakura-rental-server'), '', ['response' => 500]);
    }
}

function sakura_auto_login_expected_signature(string $user_id, int $expires_at): string {
    // 64文字HEXのHMAC署名
    return hash_hmac('sha256', "{$user_id}|{$expires_at}", AUTH_KEY);
}

/**
 * トークン配列を取得
 *
 * @return array
 */
function sakura_auto_login_get_all_tokens() {
    // NOTE: オブジェクトキャッシュ有効時、キャッシュが残る場合がある
    wp_cache_delete(SAKURA_AUTO_LOGIN_TOKENS_OPTION, 'options');
    $tokens = get_option(SAKURA_AUTO_LOGIN_TOKENS_OPTION);
    if (!is_array($tokens)) {
        $tokens = [];
    }
    $now = time();
    $tokens = array_filter($tokens, function($item) use ($now) {
        return isset($item['expiresAt']) && $item['expiresAt'] >= $now;
    });
    return is_array($tokens) ? $tokens : [];
}

/**
 * トークン配列を保存
 *
 * @param array $tokens
 * @return void
 */
function sakura_auto_login_set_all_tokens(array $tokens) {
    // NOTE: alloptionsのキャッシュに乗らないように 'no' を指定している
    update_option(SAKURA_AUTO_LOGIN_TOKENS_OPTION, $tokens, 'no');
    // NOTE: オブジェクトキャッシュ有効時、キャッシュが残る場合がある
    wp_cache_delete(SAKURA_AUTO_LOGIN_TOKENS_OPTION, 'options');
}


/**
 * トークンを追加
 *
 * @param array $token_data
 * @return void
 */
function sakura_auto_login_add_token(array $token_data) {
    $tokens = sakura_auto_login_get_all_tokens();
    $tokens[] = $token_data;
    sakura_auto_login_set_all_tokens($tokens);
}

/**
 * トークンを削除
 *
 * @param string $token
 * @return void
 */
function sakura_auto_login_delete_token(string $token) {
    $tokens = sakura_auto_login_get_all_tokens();
    $tokens = array_filter($tokens, function($item) use ($token) {
        return isset($item['token']) && $item['token'] !== $token;
    });
    sakura_auto_login_set_all_tokens(array_values($tokens));
}

/**
 * トークンを検索
 *
 * @param string $token
 * @return array|false
 */
function sakura_auto_login_find_token(string $token) {
    $tokens = sakura_auto_login_get_all_tokens();
    foreach ($tokens as $item) {
        if (isset($item['token']) && $item['token'] === $token) {
            return $item;
        }
    }
    return false;
}
