'use strict'

const assert = require('node:assert/strict')
const net = require('node:net')
const os = require('node:os')
const path = require('node:path')
const { afterEach, beforeEach, describe, it } = require('node:test')

const { makeConnection, makePlugin } = require('haraka-test-fixtures')

// A minimal fake Dovecot auth-userdb server.
//
//   1. on connect it sends the VERSION handshake line
//   2. when the plugin replies with its USER request, it answers with
//      `reply` (a complete protocol line)
//
// `opts.silent`        - accept the socket but never write anything (timeout)
// `opts.onConnect(sock)`- escape hatch for bespoke behaviour
function fakeDovecot(reply, opts = {}) {
  const server = net.createServer((sock) => {
    sock.on('error', () => {}) // a reset peer is expected in some cases
    if (opts.onConnect) return opts.onConnect(sock)
    if (opts.silent) return
    sock.write('VERSION\t1\t0\n')
    sock.once('data', () => {
      sock.write(reply, () => {
        if (opts.thenDestroy) sock.destroy(new Error('peer reset'))
        if (opts.thenExtra) sock.write(opts.thenExtra)
      })
    })
  })
  return server
}

function listen(server) {
  return new Promise((resolve) => {
    server.listen(0, '127.0.0.1', () => resolve(server.address().port))
  })
}

function _set_up() {
  this.plugin = makePlugin('dovecot', { register: false })
  this.connection = makeConnection({ withTxn: true })
  this.servers = []
}

async function startServer(reply, opts) {
  const server = fakeDovecot(reply, opts)
  const port = await listen(server)
  this.servers.push(server)
  return port
}

async function startUnixServer(reply) {
  const sockPath = path.join(
    os.tmpdir(),
    `dovecot-test-${process.pid}-${this.servers.length}.sock`,
  )
  const server = fakeDovecot(reply)
  await new Promise((resolve) => server.listen(sockPath, resolve))
  this.servers.push(server)
  return sockPath
}

function _tear_down() {
  for (const s of this.servers || []) s.close()
}

describe('register', function () {
  beforeEach(_set_up)

  it('loads dovecot.ini on register', function () {
    this.plugin.register()
    assert.equal(this.plugin.cfg.main.check_outbound, true)
  })

  it('registers the mail and rcpt hooks', function () {
    this.plugin.register()
    assert.deepEqual(this.plugin.hooks.rcpt, ['check_rcpt_on_dovecot'])
    assert.deepEqual(this.plugin.hooks.mail, ['check_mail_on_dovecot'])
  })
})

describe('load_dovecot_ini', function () {
  beforeEach(_set_up)

  it('reads the bundled config', function () {
    this.plugin.load_dovecot_ini()
    assert.equal(this.plugin.cfg.main.path, '/var/run/dovecot/auth-userdb')
  })
})

describe('check_dovecot_response', function () {
  beforeEach(_set_up)

  it('VERSION handshake -> CONT', function () {
    const [code] = this.plugin.check_dovecot_response('VERSION\t1\t0\n')
    assert.equal(code, CONT)
  })

  it('USER reply -> OK', function () {
    const [code, msg] = this.plugin.check_dovecot_response(
      'USER\t1\tuser@example.com\tuid=1000\n',
    )
    assert.equal(code, OK)
    assert.equal(msg, 'Mailbox found.')
  })

  it('FAIL reply -> DENYSOFT', function () {
    const [code] = this.plugin.check_dovecot_response('FAIL\t1\n')
    assert.equal(code, DENYSOFT)
  })

  it('unknown / NOTFOUND reply -> undefined', function () {
    const [code, msg] = this.plugin.check_dovecot_response('NOTFOUND\t1\n')
    assert.equal(code, undefined)
    assert.equal(msg, 'Mailbox not found.')
  })

  it('a USER reply without a trailing newline is not OK', function () {
    const [code] = this.plugin.check_dovecot_response('USER\t1\tx@y.z')
    assert.equal(code, undefined)
  })
})

describe('get_dovecot_response', function () {
  beforeEach(_set_up)
  afterEach(_tear_down)

  it('resolves [OK] when the mailbox is found', async function () {
    const port = await startServer.call(
      this,
      'USER\t1\tuser@example.com\tuid=1000\n',
    )
    this.plugin.cfg = { main: { host: '127.0.0.1', port } }

    const result = await this.plugin.get_dovecot_response(
      this.connection,
      'example.com',
      'user@example.com',
    )
    assert.deepEqual(result, [OK, 'Mailbox found.'])
  })

  it('resolves [undefined] when the mailbox is not found', async function () {
    const port = await startServer.call(this, 'NOTFOUND\t1\n')
    this.plugin.cfg = { main: { host: '127.0.0.1', port } }

    const result = await this.plugin.get_dovecot_response(
      this.connection,
      'example.com',
      'nope@example.com',
    )
    assert.deepEqual(result, [undefined, 'Mailbox not found.'])
  })

  it('resolves [DENYSOFT] on a FAIL reply', async function () {
    const port = await startServer.call(this, 'FAIL\t1\n')
    this.plugin.cfg = { main: { host: '127.0.0.1', port } }

    const result = await this.plugin.get_dovecot_response(
      this.connection,
      'example.com',
      'user@example.com',
    )
    assert.equal(result[0], DENYSOFT)
  })

  it('prefers a per-domain socket over main', async function () {
    const port = await startServer.call(this, 'USER\t1\tuser@example.com\n')
    this.plugin.cfg = {
      main: { host: '127.0.0.1', port: 1 }, // unroutable on purpose
      'example.com': { host: '127.0.0.1', port },
    }

    const result = await this.plugin.get_dovecot_response(
      this.connection,
      'example.com',
      'user@example.com',
    )
    assert.deepEqual(result, [OK, 'Mailbox found.'])
  })

  it('rejects when the connection is refused', async function () {
    // bind+close to obtain a port guaranteed to have no listener
    const tmp = net.createServer()
    const port = await listen(tmp)
    await new Promise((r) => tmp.close(r))
    this.plugin.cfg = { main: { host: '127.0.0.1', port } }

    await assert.rejects(
      this.plugin.get_dovecot_response(
        this.connection,
        'example.com',
        'user@example.com',
      ),
    )
  })

  it('rejects with a timeout when the server never answers', async function () {
    const port = await startServer.call(this, '', { silent: true })
    this.plugin.cfg = { main: { host: '127.0.0.1', port, timeout: 0.05 } }

    await assert.rejects(
      this.plugin.get_dovecot_response(
        this.connection,
        'example.com',
        'user@example.com',
      ),
      /timeout/,
    )
  })

  it('settles once: an error after the reply does not reject', async function () {
    const port = await startServer.call(this, 'USER\t1\tuser@example.com\n', {
      thenDestroy: true,
    })
    this.plugin.cfg = { main: { host: '127.0.0.1', port } }

    const result = await this.plugin.get_dovecot_response(
      this.connection,
      'example.com',
      'user@example.com',
    )
    assert.deepEqual(result, [OK, 'Mailbox found.'])
  })

  it('connects via a per-domain unix socket path', async function () {
    const sockPath = await startUnixServer.call(
      this,
      'USER\t1\tuser@example.com\n',
    )
    this.plugin.cfg = {
      main: { host: '127.0.0.1', port: 1 },
      'example.com': { path: sockPath },
    }

    const result = await this.plugin.get_dovecot_response(
      this.connection,
      'example.com',
      'user@example.com',
    )
    assert.deepEqual(result, [OK, 'Mailbox found.'])
  })

  it('connects via the main unix socket path', async function () {
    const sockPath = await startUnixServer.call(
      this,
      'USER\t1\tuser@example.com\n',
    )
    this.plugin.cfg = { main: { path: sockPath } }

    const result = await this.plugin.get_dovecot_response(
      this.connection,
      'no-such-domain.com',
      'user@example.com',
    )
    assert.deepEqual(result, [OK, 'Mailbox found.'])
  })

  it('settles once: extra data after the reply is ignored', async function () {
    const port = await startServer.call(this, 'USER\t1\tuser@example.com\n', {
      thenExtra: 'FAIL\t1\n',
    })
    this.plugin.cfg = { main: { host: '127.0.0.1', port } }

    const result = await this.plugin.get_dovecot_response(
      this.connection,
      'example.com',
      'user@example.com',
    )
    assert.deepEqual(result, [OK, 'Mailbox found.'])
  })
})

describe('check_mail_on_dovecot', function () {
  beforeEach(_set_up)

  const mail_params = (addr = 'user@example.com', host = 'example.com') => [
    { address: addr, host },
  ]

  it('skips when check_outbound is disabled', function (t, done) {
    this.plugin.cfg = { main: { check_outbound: false } }
    this.plugin.check_mail_on_dovecot(
      (code) => {
        assert.equal(code, undefined)
        done()
      },
      this.connection,
      mail_params(),
    )
  })

  it('skips a null sender (relayed IP)', function (t, done) {
    this.plugin.cfg = { main: { check_outbound: true } }
    this.plugin.check_mail_on_dovecot(
      (code) => {
        assert.equal(code, undefined)
        const r = this.connection.transaction.results.get('dovecot')
        assert.ok(r.skip.includes('mail_from.null'))
        done()
      },
      this.connection,
      [{ address: '', host: 'example.com' }],
    )
  })

  it('marks the sender local on OK', function (t, done) {
    this.plugin.cfg = { main: { check_outbound: true } }
    this.plugin.get_dovecot_response = async () => [OK, 'verified']
    this.plugin.check_mail_on_dovecot(
      (code) => {
        assert.equal(code, undefined)
        assert.equal(this.connection.transaction.notes.local_sender, true)
        done()
      },
      this.connection,
      mail_params(),
    )
  })

  it('continues on an unknown mailbox', function (t, done) {
    this.plugin.cfg = { main: { check_outbound: true } }
    this.plugin.get_dovecot_response = async () => [undefined, 'not found']
    this.plugin.check_mail_on_dovecot(
      (code) => {
        assert.equal(code, undefined)
        const r = this.connection.transaction.results.get('dovecot')
        assert.ok(r.err.includes('mail_from.not found'))
        done()
      },
      this.connection,
      mail_params(),
    )
  })

  it('returns CONT on a soft-fail result', function (t, done) {
    this.plugin.cfg = { main: { check_outbound: true } }
    this.plugin.get_dovecot_response = async () => [DENYSOFT, 'broken']
    this.plugin.check_mail_on_dovecot(
      (code, msg) => {
        assert.equal(code, CONT)
        assert.equal(msg, 'mail_from.broken')
        done()
      },
      this.connection,
      mail_params(),
    )
  })

  it('DENYSOFT when get_dovecot_response rejects', function (t, done) {
    this.plugin.cfg = { main: { check_outbound: true } }
    this.plugin.get_dovecot_response = async () => {
      throw new Error('boom')
    }
    this.plugin.check_mail_on_dovecot(
      (code, msg) => {
        assert.equal(code, DENYSOFT)
        assert.equal(msg, 'boom')
        done()
      },
      this.connection,
      mail_params(),
    )
  })
})

describe('check_rcpt_on_dovecot', function () {
  beforeEach(_set_up)

  const rcpt = (addr = 'user@example.com', host = 'example.com') => [
    { address: addr, host },
  ]

  it('returns OK when the mailbox exists', function (t, done) {
    this.plugin.get_dovecot_response = async () => [OK, 'found']
    this.plugin.check_rcpt_on_dovecot(
      (code) => {
        assert.equal(code, OK)
        done()
      },
      this.connection,
      rcpt(),
    )
  })

  it('accepts any rcpt for a relaying local sender', function (t, done) {
    this.plugin.get_dovecot_response = async () => [undefined, 'not found']
    this.connection.relaying = true
    this.connection.transaction.notes.local_sender = true
    this.plugin.check_rcpt_on_dovecot(
      (code) => {
        assert.equal(code, OK)
        done()
      },
      this.connection,
      rcpt(),
    )
  })

  it('continues (no decision) when the mailbox is unknown', function (t, done) {
    this.plugin.get_dovecot_response = async () => [undefined, 'unknown']
    this.plugin.check_rcpt_on_dovecot(
      (code) => {
        assert.equal(code, undefined)
        done()
      },
      this.connection,
      rcpt(),
    )
  })

  it('returns CONT on a soft-fail result', function (t, done) {
    this.plugin.get_dovecot_response = async () => [DENYSOFT, 'broken']
    this.plugin.check_rcpt_on_dovecot(
      (code, msg) => {
        assert.equal(code, CONT)
        assert.equal(msg, 'broken')
        done()
      },
      this.connection,
      rcpt(),
    )
  })

  it('DENYSOFT when get_dovecot_response rejects', function (t, done) {
    this.plugin.get_dovecot_response = async () => {
      throw new Error('socket exploded')
    }
    this.plugin.check_rcpt_on_dovecot(
      (code, msg) => {
        assert.equal(code, DENYSOFT)
        assert.equal(msg, 'error validating email address')
        done()
      },
      this.connection,
      rcpt(),
    )
  })

  it('returns early without a transaction', function () {
    this.connection.transaction = null
    const ret = this.plugin.check_rcpt_on_dovecot(
      () => assert.fail('next should not be called'),
      this.connection,
      rcpt(),
    )
    // async fn returns a promise that resolves to undefined
    return ret
  })
})
