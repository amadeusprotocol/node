import { createReadStream } from 'node:fs';
import { createHash } from 'node:crypto';
import { createInterface } from 'node:readline';
import { integer } from './store.mjs';

export async function getJson(url, fetcher = fetch) {
  const response = await fetcher(url, { signal: AbortSignal.timeout(30000), redirect: 'error' });
  if (!response.ok) throw new Error(`Source HTTP ${response.status}`);
  // Bound responses even for chunked sources; never buffer arbitrary RPC output.
  const reader = response.body.getReader();
  const chunks = []; let length = 0;
  try {
    while (true) {
      const { done, value } = await reader.read();
      if (done) break;
      length += value.length;
      if (length > 32 * 1024 * 1024) throw new Error('Source response exceeds 32 MiB');
      chunks.push(value);
    }
    return JSON.parse(Buffer.concat(chunks).toString('utf8'));
  } finally { await reader.cancel(); }
}

export async function sync(store, rpc, limit = 100, fetcher = fetch) {
  integer(limit, 'limit');
  if (limit < 1 || limit > 10000) throw new Error('Limit must be 1..10000');
  const base = new URL(rpc);
  if (!['http:','https:'].includes(base.protocol) || base.username || base.password) throw new Error('Invalid RPC URL');
  const read = path => getJson(new URL(path,base),fetcher);
  const status = await read('/api/chain/metrics/status');
  if (status.error !== 'ok' || status.schema_version !== 1 || status.chain_id !== store.chainId) throw new Error('Wrong chain or unsupported node');
  integer(status.rooted_height,'rooted height'); integer(status.pruned_below_height,'pruned height');
  const tip = store.tip();
  if (tip && status.rooted_height < tip.height) {
    store.quarantine();
    throw new Error('Rooted height moved behind checkpoint; reconcile source and rebuild');
  }
  if (tip) {
    // Check the durable checkpoint on every restart/batch. A changed root or
    // pruned checkpoint is an operator-visible failure, not a silent skip.
    store.ingest(await read(`/api/chain/metrics/block/${tip.height}`));
  }
  let height = tip ? tip.height+1 : store.startHeight;
  if (height < status.pruned_below_height) throw new Error('Archive required: source pruned requested history');
  let indexed = 0;
  while (height <= status.rooted_height && indexed < limit) {
    const data = await read(`/api/chain/metrics/block/${height}`);
    if (data.block?.height !== height) throw new Error('RPC returned wrong height');
    store.ingest(data);
    height++; indexed++;
  }
  return { indexed, next_height:height, rooted_height:status.rooted_height };
}

export async function importTimes(store, path, { sourceUrl, sha256 }) {
  const url = new URL(sourceUrl);
  if (url.protocol !== 'https:' || url.username || url.password || !/^[a-f0-9]{64}$/.test(sha256)) throw new Error('Require public HTTPS provenance URL and SHA-256');
  // Operator must review the archive's time methodology. SHA pins its bytes;
  // it does not prove that its timestamps are consensus-authenticated.
  const input = createReadStream(path);
  const hash = createHash('sha256');
  input.on('data', bytes => hash.update(bytes));
  const lines = createInterface({ input, crlfDelay:Infinity });
  let count = 0;
  store.db.exec('BEGIN IMMEDIATE');
  try {
    store.db.prepare('INSERT OR IGNORE INTO time_sources VALUES(?,?)').run(sha256,sourceUrl);
    for await (const line of lines) {
      if (!line.trim()) continue;
      store.setTime(JSON.parse(line),sha256); count++;
    }
    if (hash.digest('hex') !== sha256) throw new Error('Archive SHA-256 mismatch');
    store.db.exec('COMMIT');
    return { imported:count, sha256 };
  } catch (error) { store.db.exec('ROLLBACK'); throw error; }
  finally { lines.close(); input.destroy(); }
}
