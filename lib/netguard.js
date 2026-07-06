// Shared SSRF guard: refuse URLs whose host resolves to private, loopback,
// link-local, CGNAT, or cloud-metadata address space (IPv4 and IPv6).
// Used by launch-check and scan-url before touching any user-supplied URL.

import dns from 'node:dns';
import net from 'node:net';

function privateV4(ip) {
  const p = ip.split('.').map(Number);
  if (p.length !== 4 || p.some(n => Number.isNaN(n))) return true; // malformed = refuse
  const [a, b] = p;
  return (
    a === 0 || a === 10 || a === 127 ||
    (a === 100 && b >= 64 && b <= 127) ||      // CGNAT
    (a === 169 && b === 254) ||                 // link-local / cloud metadata
    (a === 172 && b >= 16 && b <= 31) ||
    (a === 192 && b === 168) ||
    (a === 192 && b === 0) ||                   // 192.0.0.0/24 special
    (a === 198 && (b === 18 || b === 19)) ||    // benchmarking
    a >= 224                                    // multicast + reserved + broadcast
  );
}

function privateV6(ip) {
  const s = ip.toLowerCase();
  if (s === '::' || s === '::1') return true;
  if (s.startsWith('fc') || s.startsWith('fd')) return true;              // ULA fc00::/7
  if (/^fe[89ab]/.test(s)) return true;                                    // link-local fe80::/10
  const mapped = s.match(/^::ffff:(\d+\.\d+\.\d+\.\d+)$/);                 // v4-mapped
  if (mapped) return privateV4(mapped[1]);
  if (s.startsWith('64:ff9b')) return true;                                // NAT64 — refuse
  return false;
}

function privateIp(ip) {
  const v = net.isIP(ip);
  if (v === 4) return privateV4(ip);
  if (v === 6) return privateV6(ip);
  return true; // not an IP = refuse here (hostnames go through lookup first)
}

// Throws with a user-safe message if the URL must not be fetched.
export async function assertPublicUrl(urlObj) {
  const host = urlObj.hostname.replace(/^\[|\]$/g, ''); // strip IPv6 brackets
  const lower = host.toLowerCase();
  if (lower === 'localhost' || lower.endsWith('.localhost') ||
      lower.endsWith('.local') || lower.endsWith('.internal') ||
      lower.endsWith('.home.arpa')) {
    throw new Error('Cannot check private/internal addresses.');
  }
  if (net.isIP(host)) {
    if (privateIp(host)) throw new Error('Cannot check private/internal addresses.');
    return;
  }
  let addrs;
  try {
    addrs = await dns.promises.lookup(host, { all: true, verbatim: true });
  } catch (e) {
    throw new Error('Could not resolve that domain. Check the URL.');
  }
  if (!addrs.length) throw new Error('Could not resolve that domain. Check the URL.');
  for (const a of addrs) {
    if (privateIp(a.address)) throw new Error('Cannot check private/internal addresses.');
  }
}
