'use strict';

const net = require('node:net');

exports.register = function () {
  this.register_hook('rcpt', 'check_rcpt_on_dovecot');
  this.register_hook('mail', 'check_mail_on_dovecot');
};

exports.load_dovecot_ini = function () {
  const plugin = this;
  plugin.cfg = plugin.config.get("dovecot.ini", function () {
    plugin.load_dovecot_ini();
  });
};

exports.check_mail_on_dovecot = function (next, connection, params) {
  const plugin = this;

  if (!plugin.cfg.main.check_outbound) return next();

  // determine if MAIL FROM domain is local
  const txn = connection.transaction;

  const email = params[0].address();
  if (!email) {
    // likely an IP with relaying permission
    txn.results.add(plugin, { skip: "mail_from.null", emit: true });
    return next();
  }

  const domain = params[0].host.toLowerCase();

  plugin.get_dovecot_response(connection, domain, email, (err, result) => {
    if (err) {
      txn.results.add(plugin, { err });
      return next(DENYSOFT, err);
    }

    // the MAIL FROM sender is verified as a local address
    if (result[0] === OK) {
      txn.results.add(plugin, { pass: `mail_from.${result[1]}` });
      txn.notes.local_sender = true;
      return next();
    }

    if (result[0] === undefined) {
      txn.results.add(plugin, { err: `mail_from.${result[1]}` });
      return next();
    }

    txn.results.add(plugin, { msg: `mail_from.${result[1]}` });
    next(CONT, `mail_from.${result[1]}`);
  });
};

exports.check_rcpt_on_dovecot = function (next, connection, params) {
  const plugin = this;
  const txn = connection.transaction;
  if (!txn) return;

  const rcpt = params[0];
  const domain = rcpt.host.toLowerCase();

  // Qmail::Deliverable::Client does a rfc2822 "atext" test
  // but Haraka has already validated for us by this point
  plugin.get_dovecot_response(
    connection,
    domain,
    rcpt.address(),
    (err, result) => {
      if (err) {
        connection.logerror(plugin, err);
        txn.results.add(plugin, { err });
        return next(DENYSOFT, "error validating email address");
      }

      if (result[0] === OK) {
        txn.results.add(plugin, { pass: `rcpt.${result[1]}` });
        return next(OK);
      }

      // a client with relaying privileges is sending from a local domain.
      // Any RCPT is acceptable.
      if (connection.relaying && txn.notes.local_sender) {
        txn.results.add(plugin, { pass: "relaying local_sender" });
        return next(OK);
      }

      if (result[0] === undefined) {
        txn.results.add(plugin, { err: `rcpt.${result[1]}` });
        return next();
      }

      // no need to DENY[SOFT] for invalid addresses. If no rcpt_to.* plugin
      // returns OK, then the address is not accepted.
      txn.results.add(plugin, { msg: `rcpt.${result[1]}` });
      next(CONT, result[1]);
    },
  );
};

exports.get_dovecot_response = function (connection, domain, email, cb) {
  const plugin = this;
  const options = {};

  if (plugin.cfg[domain]) {
    if (plugin.cfg[domain].path) {
      options.path = plugin.cfg[domain].path;
    } else {
      if (plugin.cfg[domain].host) {
        options.host = plugin.cfg[domain].host;
      }
      if (plugin.cfg[domain].port) {
        options.port = plugin.cfg[domain].port;
      }
    }
  } else {
    if (plugin.cfg.main.path) {
      options.path = plugin.cfg.main.path;
    } else {
      if (plugin.cfg.main.host) options.host = plugin.cfg.main.host;
      if (plugin.cfg.main.port) options.port = plugin.cfg.main.port;
    }
  }

  connection.transaction.results.add(plugin, {
    msg: `sock: ${options.host}:${options.port}`,
  });

  connection.logdebug(plugin, `checking ${email}`);
  const client = net.connect(options, function () {
    //'connect' listener
    connection.logprotocol(
      plugin,
      `connect to Dovecot auth-master:${JSON.stringify(options)}`,
    );
  });

  client
    .on("data", (chunk) => {
      connection.logprotocol(plugin, `BODY: ${chunk}`);
      const arr = exports.check_dovecot_response(chunk.toString());
      if (arr[0] === CONT) {
        const send_data = `${"VERSION\t1\t0\n" + "USER\t1\t"}${email}\tservice=smtp\n`;
        client.write(send_data);
      } else {
        cb(undefined, arr);
      }
    })
    .on("error", (e) => {
      client.end();
      cb(e);
    })
    .on("end", () => {
      connection.logprotocol(plugin, "closed connect to Dovecot auth-master");
    });
};

exports.check_dovecot_response = function (data) {
  if (data.match(/^VERSION\t\d+\t/i) && data.slice(-1) === "\n") {
    return [CONT, "Send now username to check process."];
  } else if (data.match(/^USER\t1/i) && data.slice(-1) === "\n") {
    return [OK, "Mailbox found."];
  } else if (data.match(/^FAIL\t1/i) && data.slice(-1) === "\n") {
    return [
      DENYSOFT,
      "Temporarily undeliverable: internal communication broken",
    ];
  } else {
    return [undefined, "Mailbox not found."];
  }
};
