=== Auto Login for Sakura Rental Server ===
Contributors: sakurainternet
Tags: login, auto-login, token, cli
Requires at least: 5.0
Tested up to: 6.8
Requires PHP: 7.4
Stable tag: 1.0.5
License: GPLv3 or later
License URI: https://www.gnu.org/licenses/gpl-3.0.html
Text Domain: auto-login-for-sakura-rental-server
Domain Path: /languages

Provides one-time auto-login URLs with HMAC signatures and time limits.

== Description ==
**Auto Login for Sakura Rental Server** allows administrators to issue one-time, time-limited auto-login URLs using HMAC signatures.  
This is useful for secure temporary access or system integration.

Features:
- Secure auto-login with one-time tokens
- Tokens are HMAC-signed and invalidated after use
- Token issuance and usage history (up to 100 entries per user)
- Records IP address and username of the issuer
- Rate limiting: 1 request per second per IP
- WP-CLI commands for token generation and history inspection

Example use cases:
- Temporarily granting admin access
- Safe automatic login from external systems
- Keeping an audit log of who issued a token and from where

== Installation ==
1. Upload the plugin to `/wp-content/plugins/auto-login-for-sakura-rental-server/`.
2. Activate it through the **Plugins** menu in WordPress.

== Usage ==

=== Generate a token via CLI ===


    wp auto-login-for-sakura-rental-server generate <user_id> [–expires=] [–remote_addr=] [–username=]


Example:

- Default expiration time: 300 seconds  
- `--expires` and `--username` are optional

=== Check issue history ===
Token history is stored in the user meta key `sakura_auto_login_history`.  
You can check it via WP-CLI:

wp user meta get <user_id> sakura_auto_login_history

=== Auto-login URL format ===


    https://example.com/?rs_auto_login_token=<64-character HMAC token>


Visiting the URL will log in as the corresponding user and redirect to the admin dashboard.

== Security Notes ==
- Tokens are invalidated immediately after use (one-time only)
- Issue and usage history includes IP address, issuer username, and timestamps
- Stored using `update_option()` for caching compatibility
- HTTPS is strongly recommended

== Frequently Asked Questions ==

= Can I revoke a token manually? =
Yes. Run `sakura_auto_login_delete_token('<token>')`.

= What happens if the URL leaks? =
Anyone with the URL can log in as the target user until the token expires. Always use HTTPS and handle URLs carefully.

== Changelog ==
= 1.0.0 =
* Initial release

= 1.0.1 =
* Bugfix release

= 1.0.2 =
* Internal changes release

= 1.0.3 =
* Readme changes release

= 1.0.4 =
* Readme changes release

= 1.0.5 =
* Bugfix release

== Upgrade Notice ==
= 1.0.1 =
* Fixed a bug. Users should update.

= 1.0.2 =
* Internal changes. Users should update.

= 1.0.3 =
* Readme changes only.

= 1.0.4 =
* Readme changes only.

= 1.0.5 =
* Fixed a bug. Users should update.
