'use strict'

const net = require('node:net')

exports.register = function () {
  this.load_dovecot_ini()
  this.register_hook('rcpt', 'check_rcpt_on_dovecot')
  this.register_hook('mail', 'check_mail_on_dovecot')
}

exports.load_dovecot_ini = function () {
  this.cfg = this.config.get(
    'dovecot.ini',
    { booleans: ['+main.check_outbound'] },
    () => {
      this.load_dovecot_ini()
    },
  )
}

exports.check_mail_on_dovecot = async function (next, connection, params) {
  if (!this.cfg.main.check_outbound) return next()

  const addr = params?.[0]
  if (!addr) return next()

  const txn = connection.transaction

  const email = addr.address
  if (!email) {
    // likely an IP with relaying permission
    txn.results.add(this, { skip: 'mail_from.null', emit: true })
    return next()
  }

  const domain = addr.host?.toLowerCase()
  if (!domain) return next()

  let result
  try {
    result = await this.get_dovecot_response(connection, domain, email)
  } catch (err) {
    txn.results.add(this, { err })
    return next(DENYSOFT, err.message)
  }

  // the MAIL FROM sender is verified as a local address
  if (result[0] === OK) {
    txn.results.add(this, { pass: `mail_from.${result[1]}` })
    txn.notes.local_sender = true
    return next()
  }

  if (result[0] === undefined) {
    txn.results.add(this, { err: `mail_from.${result[1]}` })
    return next()
  }

  txn.results.add(this, { msg: `mail_from.${result[1]}` })
  next(CONT, `mail_from.${result[1]}`)
}

exports.check_rcpt_on_dovecot = async function (next, connection, params) {
  const plugin = this
  const txn = connection.transaction
  if (!txn) return next()

  const rcpt = params?.[0]
  if (!rcpt) return next()

  const domain = rcpt.host?.toLowerCase()
  if (!domain) return next()

  let result
  try {
    result = await plugin.get_dovecot_response(connection, domain, rcpt.address)
  } catch (err) {
    connection.logerror(plugin, err.message)
    txn.results.add(plugin, { err })
    return next(DENYSOFT, 'error validating email address')
  }

  if (result[0] === OK) {
    txn.results.add(plugin, { pass: `rcpt.${result[1]}` })
    return next(OK)
  }

  // a client with relaying privileges is sending from a local domain.
  // Any RCPT is acceptable.
  if (connection.relaying && txn.notes.local_sender) {
    txn.results.add(plugin, { pass: 'relaying local_sender' })
    return next(OK)
  }

  if (result[0] === undefined) {
    txn.results.add(plugin, { err: `rcpt.${result[1]}` })
    return next()
  }

  // no need to DENY[SOFT] for invalid addresses. If no rcpt_to.* plugin
  // returns OK, then the address is not accepted.
  txn.results.add(plugin, { msg: `rcpt.${result[1]}` })
  next(CONT, result[1])
}

// Resolve the connect-options for `domain`: a per-domain socket overrides
// the global default. Returns either { path } (unix socket) or { host, port }.
exports.dovecot_socket_options = function (domain) {
  const sources = [this.cfg[domain], this.cfg.main].filter(Boolean)
  for (const src of sources) {
    if (src.path) return { path: src.path }
    if (src.host || src.port) {
      const opts = {}
      if (src.host) opts.host = src.host
      if (src.port) opts.port = src.port
      return opts
    }
  }
  return {}
}

exports.get_dovecot_response = function (connection, domain, email) {
  const plugin = this
  const options = plugin.dovecot_socket_options(domain)

  const socket_address = options.path ?? `${options.host}:${options.port}`
  connection.logdebug(plugin, `sock: ${socket_address}`)

  // milliseconds before a stuck connection is abandoned with DENYSOFT
  const timeout = (plugin.cfg.main.timeout || 30) * 1000

  connection.logdebug(plugin, `checking ${email}`)

  return new Promise((resolve, reject) => {
    const client = net.connect(options, () => {
      connection.logprotocol(
        plugin,
        `connect to Dovecot auth-userdb:${JSON.stringify(options)}`,
      )
    })

    // The original callback API could fire more than once: a second 'data'
    // chunk, or an 'error' after a response, re-invoked the caller. The
    // Promise settles exactly once; the guard also prevents writing to or
    // leaking a socket we are done with.
    let settled = false
    function finish(err, result) {
      if (settled) return
      settled = true
      client.end()
      if (err) return reject(err)
      resolve(result)
    }

    client.setTimeout(timeout, () => {
      finish(new Error(`Dovecot auth-userdb timeout after ${timeout}ms`))
    })

    // Dovecot replies must be parsed per complete protocol record
    // (newline-terminated), not per TCP chunk. Buffer until a full line
    // arrives
    let buffer = ''
    let sentUserRequest = false

    client
      .on('data', (chunk) => {
        connection.logprotocol(plugin, `BODY: ${chunk}`)
        buffer += chunk.toString()
        let nl
        while ((nl = buffer.indexOf('\n')) !== -1) {
          const line = buffer.slice(0, nl + 1)
          buffer = buffer.slice(nl + 1)
          if (
            plugin.handle_dovecot_line(
              client,
              line,
              email,
              sentUserRequest,
              finish,
            )
          ) {
            sentUserRequest = true
          } else {
            return // finish() invoked
          }
        }
      })
      .on('error', finish)
      .on('end', () => {
        connection.logprotocol(plugin, 'closed connect to Dovecot auth-userdb')
      })
  })
}

// Process one complete dovecot protocol record. Returns true if the caller
// should keep reading (we sent the USER request and are awaiting the reply);
// false if the response has been finalized (finish() was invoked).
exports.handle_dovecot_line = function (
  client,
  line,
  email,
  sentUserRequest,
  finish,
) {
  const arr = this.check_dovecot_response(line)
  if (!sentUserRequest && arr[0] === CONT) {
    client.write(`VERSION\t1\t0\nUSER\t1\t${email}\tservice=smtp\n`)
    return true
  }
  finish(undefined, arr)
  return false
}

exports.check_dovecot_response = function (data) {
  if (data.match(/^VERSION\t\d+\t/i) && data.slice(-1) === '\n') {
    return [CONT, 'Send now username to check process.']
  } else if (data.match(/^USER\t1/i) && data.slice(-1) === '\n') {
    return [OK, 'Mailbox found.']
  } else if (data.match(/^FAIL\t1/i) && data.slice(-1) === '\n') {
    return [
      DENYSOFT,
      'Temporarily undeliverable: internal communication broken',
    ]
  }
  return [undefined, 'Mailbox not found.']
}
