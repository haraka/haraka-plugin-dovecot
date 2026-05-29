# haraka-plugin-dovecot

[![Test][ci-img]][ci-url] [![Cover][cov-img]][cov-url] [![Qlty][qlty-img]][qlty-url]

Haraka mail plugin that checks whether a mailbox exists (Dovecot auth-userdb) and the SMTP-Auth per Dovecot (service auth is also used by Postfix) allowed.

## USAGE

Add plugin name `dovecot` to haraka's `config/plugins` file.

## CONFIGURE

Edit the dovecot.ini file.

<!-- leave these buried at the bottom of the document -->

[ci-img]: https://github.com/haraka/haraka-plugin-dovecot/actions/workflows/ci.yml/badge.svg
[ci-url]: https://github.com/haraka/haraka-plugin-dovecot/actions/workflows/ci.yml
[cov-img]: https://codecov.io/github/haraka/haraka-plugin-dovecot/coverage.svg
[cov-url]: https://codecov.io/github/haraka/haraka-plugin-dovecot
[qlty-img]: https://qlty.sh/gh/haraka/projects/haraka-plugin-dovecot/maintainability.svg
[qlty-url]: https://qlty.sh/gh/haraka/projects/haraka-plugin-dovecot
