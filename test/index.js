'use strict'

const assert = require('node:assert/strict')
const { beforeEach, describe, it } = require('node:test')
const fixtures = require('haraka-test-fixtures')

beforeEach(() => {
  this.plugin = new fixtures.plugin('template')

  // Conditionally inject for coverage tracking
  if (process.env.HARAKA_COVERAGE) {
    const plugin_module = require('../index.js')
    Object.assign(this.plugin, plugin_module)
  }
})

describe('register', () => {
  it('has a register function', () => {
    assert.equal('function', typeof this.plugin.register)
  })

  it('registers', () => {
    this.plugin.register()
    assert.ok(this.plugin.cfg)
  })
})
