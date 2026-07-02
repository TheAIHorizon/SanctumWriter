/**
 * SSRF guard for server-side fetches of user/remote-supplied URLs.
 *
 * Mirrors the confinement approach Phase 0 used for the file API
 * (app/api/files/route.ts's isWithin() + allowedRoots check): reject
 * anything outside an explicit allowlist rather than trying to blocklist
 * "bad" inputs. Here the allowlist is "public http(s) hosts", and the
 * denylist is loopback / private / link-local / unspecified IP ranges -
 * checked on every IP a hostname resolves to, so a public-looking domain
 * that resolves (or rebinds) to an internal address is still rejected.
 */

import { promises as dns } from 'dns';
import net from 'net';

export class UnsafeUrlError extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'UnsafeUrlError';
  }
}

/**
 * Returns true if the given IPv4/IPv6 address is loopback, private,
 * link-local (including the 169.254.169.254 cloud metadata address),
 * unique-local, or unspecified.
 */
export function isPrivateOrLoopbackIp(ip: string): boolean {
  const version = net.isIP(ip);

  if (version === 4) {
    const parts = ip.split('.').map(Number);
    if (parts.length !== 4 || parts.some((p) => Number.isNaN(p) || p < 0 || p > 255)) {
      return true; // malformed - treat as unsafe
    }
    const [a, b] = parts;

    if (a === 127) return true; // 127.0.0.0/8 loopback
    if (a === 10) return true; // 10.0.0.0/8 private
    if (a === 172 && b >= 16 && b <= 31) return true; // 172.16.0.0/12 private
    if (a === 192 && b === 168) return true; // 192.168.0.0/16 private
    if (a === 169 && b === 254) return true; // 169.254.0.0/16 link-local (incl. cloud metadata)
    if (a === 0) return true; // 0.0.0.0/8 "this network"
    if (a === 100 && b >= 64 && b <= 127) return true; // 100.64.0.0/10 CGNAT
    if (a === 192 && b === 0 && parts[2] === 0) return true; // 192.0.0.0/24 IETF protocol assignments
    if (a >= 224) return true; // 224.0.0.0+ multicast/reserved

    return false;
  }

  if (version === 6) {
    const normalized = ip.toLowerCase();
    if (normalized === '::1' || normalized === '::') return true; // loopback / unspecified
    if (normalized.startsWith('::ffff:')) {
      // IPv4-mapped IPv6 address - check the embedded IPv4 address
      const embedded = normalized.slice('::ffff:'.length);
      if (net.isIP(embedded) === 4) return isPrivateOrLoopbackIp(embedded);
    }
    if (/^fe[89ab][0-9a-f]:/.test(normalized)) return true; // fe80::/10 link-local
    if (/^f[cd][0-9a-f]{2}:/.test(normalized)) return true; // fc00::/7 unique local

    return false;
  }

  // Not a valid IP at all
  return true;
}

export interface AssertSafeExternalUrlOptions {
  /**
   * Origins (protocol + hostname + port, e.g. "http://127.0.0.1:8188")
   * that are exempt from the private/loopback IP check - for callers that
   * have a specific, user-configured local service they intentionally
   * need to reach (e.g. a local ComfyUI instance). Every other
   * private/loopback/link-local target is still rejected.
   */
  trustedOrigins?: string[];
}

/**
 * Validates that `urlString` is safe to fetch server-side:
 * - must parse as a URL
 * - protocol must be http: or https:
 * - every IP the hostname resolves to must be a public address, unless
 *   the URL's origin is explicitly listed in `trustedOrigins`
 *
 * Throws UnsafeUrlError if the URL should not be fetched.
 */
export async function assertSafeExternalUrl(
  urlString: string,
  options: AssertSafeExternalUrlOptions = {}
): Promise<URL> {
  let parsed: URL;
  try {
    parsed = new URL(urlString);
  } catch {
    throw new UnsafeUrlError('Invalid URL');
  }

  if (parsed.protocol !== 'http:' && parsed.protocol !== 'https:') {
    throw new UnsafeUrlError(`Unsupported protocol: ${parsed.protocol}`);
  }

  if (options.trustedOrigins?.includes(parsed.origin)) {
    return parsed;
  }

  const hostname = parsed.hostname;

  // If the hostname is already a literal IP, check it directly.
  if (net.isIP(hostname)) {
    if (isPrivateOrLoopbackIp(hostname)) {
      throw new UnsafeUrlError(`Refusing to fetch private/loopback address: ${hostname}`);
    }
    return parsed;
  }

  // Otherwise resolve DNS and check every returned address, to guard
  // against a public-looking hostname resolving (or rebinding) to an
  // internal IP.
  let addresses: { address: string }[];
  try {
    addresses = await dns.lookup(hostname, { all: true });
  } catch {
    throw new UnsafeUrlError(`Could not resolve hostname: ${hostname}`);
  }

  if (addresses.length === 0) {
    throw new UnsafeUrlError(`Hostname resolved to no addresses: ${hostname}`);
  }

  for (const { address } of addresses) {
    if (isPrivateOrLoopbackIp(address)) {
      throw new UnsafeUrlError(
        `Refusing to fetch ${hostname}: resolves to private/loopback address ${address}`
      );
    }
  }

  return parsed;
}
