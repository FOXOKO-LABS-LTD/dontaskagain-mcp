// prepublishOnly: refuse to publish a package whose built files or README carry what must not be published —
// references to protocol documents that are not public (`§`, the internal document name), the word "contract",
// Cyrillic, or an IPv4 address that is not loopback, private or documentation-only.
import { readdirSync, readFileSync, statSync } from 'node:fs';
import { join } from 'node:path';

const files = [];
const walk = (d) => { for (const f of readdirSync(d)) { const p = join(d, f); if (statSync(p).isDirectory()) walk(p); else files.push(p); } };
walk('dist');
files.push('README.md');

const okIp = (ip) => {
  const [a, b, c] = ip.split('.').map(Number);
  return a === 127 || a === 10 || a === 0 || (a === 192 && b === 168) || (a === 172 && b >= 16 && b <= 31) || (a === 100 && b >= 64 && b <= 127)
    || (a === 169 && b === 254) || (a === 192 && b === 0 && c === 2) || (a === 198 && b === 51 && c === 100) || (a === 203 && b === 0 && c === 113);
};
const RULES = [
  [/§/, 'a section sign'],
  [/agent-wallet-v\d/i, 'an internal document name'],
  [/contract/i, 'the word "contract"'],
  [/[Ѐ-ӿ]/, 'Cyrillic'],
];
const bad = [];
for (const f of files) {
  readFileSync(f, 'utf8').split('\n').forEach((l, i) => {
    for (const [re, why] of RULES) if (re.test(l)) bad.push(`${f}:${i + 1}: ${why}`);
    for (const m of l.matchAll(/(?<![\d.])(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})(?![\d.])/g)) if (!okIp(m[1])) bad.push(`${f}:${i + 1}: IPv4 ${m[1]}`);
  });
}
if (bad.length) { console.error(`check-publish: ${bad.length} problem(s), not publishing:\n${bad.join('\n')}`); process.exit(1); }
console.log(`check-publish: ok (${files.length} files)`);
