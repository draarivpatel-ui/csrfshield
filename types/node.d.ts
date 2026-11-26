export * from './index';
import { CryptoAdapter, ShieldOptions, Shield } from './index';

/** Native node:crypto adapter: HMAC-SHA256 and timingSafeEqual from the standard library. */
export declare const nodeCrypto: CryptoAdapter;

declare const nodeEntry: {
  readonly nodeCrypto: CryptoAdapter;
  readonly createShield: (options: ShieldOptions) => Shield;
};
export default nodeEntry;
