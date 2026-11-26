/*
 * Node.js entry point. Uses only node:crypto from the standard library.
 * The core has zero runtime dependencies and no platform-specific code.
 */
import { createRequire } from 'node:module';
import core, { createNodeCrypto } from './index.mjs';

const require = createRequire(import.meta.url);
const nodeCryptoModule = require('node:crypto');

export * from './index.mjs';
export const nodeCrypto = createNodeCrypto(nodeCryptoModule);
export default Object.assign({}, core, { nodeCrypto });
