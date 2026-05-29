# Changelog

### Unreleased

### [0.3.1] - 2026-05-29

- fix: buffer auth-userdb replies per newline
- fix: RCPT hook now calls `next()` when transaction is missing
- fix: guard `params[0]` / `host` in MAIL and RCPT hooks
- security: drop socket path/endpoint from `results`; log to debug only
- refactor: extract `dovecot_socket_options()` and `handle_dovecot_line()`
- doc: README clarifies plugin validates MAIL/RCPT via auth-userdb
- test: refactored against test-fixtures 1.7.0 #19

### [0.3.0] - 2026-05-18

- change: use @haraka/email-address syntax (vs address-rfc2821)
  - related to https://github.com/haraka/Haraka/issues/3564
- change: `get_dovecot_response` is now async (Promise) instead of callback
- change: `check_mail_on_dovecot` / `check_rcpt_on_dovecot` are now async
- fix: get_dovecot_response settles exactly once
- fix: abandon a stuck auth-userdb connection after `main.timeout` seconds
- fix: `check_outbound=false` in dovecot.ini is now honored, vs string 'false'
- fix: `sock:` result now reports the unix socket path when one is used
- test: expand test coverage
- feat: add test coverage instrumentation

### [0.2.2] - 2025-11-10

- use auth-userdb instead of auth-master #15
- load config file when registering
- doc(CHANGELOG): added
- doc(CONTRIBUTORS): added
- package.json: populate [files] section

### [0.2.0] - 2025-11-10

- add CI testing
- update eslint config
- prettier
- remove useless replace
- replace some uses of `plugin` with `this`

[0.2.2]: https://github.com/haraka/haraka-plugin-dovecot/releases/tag/v0.2.2
[0.2.0]: https://github.com/haraka/haraka-plugin-dovecot/releases/tag/v0.2.0
[0.3.0]: https://github.com/haraka/haraka-plugin-dovecot/releases/tag/v0.3.0
[0.3.1]: https://github.com/haraka/haraka-plugin-dovecot/releases/tag/v0.3.1
