'use strict';

/* Node.js CommonJS entry point. Uses only node:crypto from the standard library. */
const core = require('./index.cjs');
const nodeCrypto = core.createNodeCrypto(require('node:crypto'));

module.exports = Object.assign({}, core, { nodeCrypto });
module.exports.default = module.exports;
