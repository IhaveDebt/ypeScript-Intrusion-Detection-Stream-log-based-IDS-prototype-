/**
 * TS Intrusion Detection Stream (ids_stream.ts)
 *
 * - Ingests log lines from stdin (or file) and applies lightweight rules and anomaly scoring.
 *
 * Usage:
 *  node -r ts-node/register src/ids_stream.ts logs.txt
 *
 * Or: cat logs.txt | ts-node src/ids_stream.ts
 */
import fs from 'fs';
import readline from 'readline';

function scoreLine(line: string): number {
  let score = 0;
  if (/failed login/i.test(line)) score += 5;
  if (/sudo:\s+authentication failure/i.test(line)) score += 8;
  if (/(wget|curl).*http:\/\//i.test(line)) score += 2;
  if (/(sqlmap|nikto|nmap)/i.test(line)) score += 10;
  return score;
}

async function processStream(input: NodeJS.ReadableStream) {
  const rl = readline.createInterface({ input, crlfDelay: Infinity });
  for await (const line of rl) {
    const s = scoreLine(line);
    if (s >= 8) console.warn('[ALERT]', s, line);
    else if (s >= 4) console.log('[SUSPICIOUS]', s, line);
    else console.log('[OK]', s, line);
  }
}

// if argument is a file, read it, else stdin
const file = process.argv[2];
if (file && fs.existsSync(file)) {
  processStream(fs.createReadStream(file));
} else {
  console.log('Reading from stdin. Send log lines or pass a filename.');
  processStream(process.stdin);
}
