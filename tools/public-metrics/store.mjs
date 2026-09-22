import { DatabaseSync } from 'node:sqlite';
import { createHash } from 'node:crypto';

export const METHODOLOGY = {
  version: 'amadeus-activity-v1',
  transactions: 'All transactions in canonical rooted blocks, including failed executions.',
  successful_transactions: 'Transactions with an explicit successful execution receipt.',
  unique_active_addresses: 'Distinct transaction signers with at least one successful execution; addresses are not people.',
  new_addresses: 'Signers making their first successful transaction, only when history is indexed from genesis.',
  time: 'UTC [start,end) from an operator-reviewed, hash-pinned external block-time archive. Amadeus block headers contain no UTC time. No nonce, block-interval or node-seentime estimates.',
};

export function integer(value, name) {
  if (!Number.isSafeInteger(value) || value < 0) throw new Error(`Invalid ${name}`);
  return value;
}

function identifier(value, name) {
  if (typeof value !== 'string' || !/^[1-9A-HJ-NP-Za-km-z]{1,100}$/.test(value)) throw new Error(`Invalid ${name}`);
  return value;
}

export function dayWindow(date) {
  if (typeof date !== 'string' || !/^\d{4}-\d{2}-\d{2}$/.test(date)) throw new Error('Expected YYYY-MM-DD');
  const start = Date.parse(`${date}T00:00:00Z`) / 1000;
  if (!Number.isSafeInteger(start) || start < 0 || new Date(start * 1000).toISOString().slice(0, 10) !== date) throw new Error('Invalid date');
  return [start, start + 86400];
}

export class MetricsStore {
  constructor(path, { chainId, startHeight = 0 }) {
    identifier(chainId, 'chain id');
    integer(startHeight, 'start height');
    this.db = new DatabaseSync(path);
    this.db.exec(`PRAGMA journal_mode=WAL; PRAGMA foreign_keys=ON; PRAGMA busy_timeout=5000;
      CREATE TABLE IF NOT EXISTS config (id INTEGER PRIMARY KEY CHECK(id=1), chain_id TEXT NOT NULL, start_height INTEGER NOT NULL);
      CREATE TABLE IF NOT EXISTS blocks (height INTEGER PRIMARY KEY, hash TEXT UNIQUE NOT NULL, previous_hash TEXT NOT NULL, digest TEXT NOT NULL, timestamp INTEGER, time_source TEXT);
      CREATE INDEX IF NOT EXISTS block_times ON blocks(timestamp);
      CREATE TABLE IF NOT EXISTS transactions (hash TEXT PRIMARY KEY, height INTEGER NOT NULL REFERENCES blocks(height), signer TEXT NOT NULL, success INTEGER NOT NULL CHECK(success IN (0,1))) WITHOUT ROWID;
      CREATE INDEX IF NOT EXISTS tx_height ON transactions(height);
      CREATE TABLE IF NOT EXISTS first_signers (signer TEXT PRIMARY KEY, height INTEGER NOT NULL REFERENCES blocks(height)) WITHOUT ROWID;
      CREATE INDEX IF NOT EXISTS first_height ON first_signers(height);
      CREATE TABLE IF NOT EXISTS time_sources (digest TEXT PRIMARY KEY, url TEXT NOT NULL);
      CREATE TABLE IF NOT EXISTS integrity (id INTEGER PRIMARY KEY CHECK(id=1), reason TEXT NOT NULL);
    `);
    this.db.prepare('INSERT OR IGNORE INTO config VALUES (1,?,?)').run(chainId, startHeight);
    const saved = this.db.prepare('SELECT * FROM config').get();
    if (saved.chain_id !== chainId || saved.start_height !== startHeight) {
      this.db.close();
      throw new Error('Database belongs to another chain or starting height');
    }
    this.chainId = chainId;
    this.startHeight = startHeight;
  }

  close() { this.db.close(); }
  tip() { return this.db.prepare('SELECT height,hash FROM blocks ORDER BY height DESC LIMIT 1').get() ?? null; }
  quarantine() { this.db.prepare('INSERT OR REPLACE INTO integrity VALUES(1,?)').run('source_history_conflict'); }

  ingest(response) {
    if (this.db.prepare('SELECT reason FROM integrity').get()) throw new Error('Index quarantined; reconcile source and rebuild');
    if (response?.error !== 'ok' || response.schema_version !== 1 || response.chain_id !== this.chainId) throw new Error('Invalid source response or wrong chain');
    const b = response.block;
    integer(b?.height, 'height');
    identifier(b.hash, 'block hash');
    if (!(b.height === 0 && b.previous_hash === '')) identifier(b.previous_hash, 'previous hash');
    if (b.finalized !== true || b.timestamp !== null || b.timestamp_basis !== 'unavailable') throw new Error('Expected rooted block with no inferred timestamp');
    if (!Array.isArray(b.transactions) || b.transactions.length !== b.transaction_count) throw new Error('Incomplete transactions');
    const ids = new Set();
    for (const tx of b.transactions) {
      identifier(tx.hash, 'transaction hash'); identifier(tx.signer, 'signer');
      if (typeof tx.success !== 'boolean' || ids.has(tx.hash)) throw new Error('Missing receipt or duplicate transaction');
      ids.add(tx.hash);
    }
    const digest = createHash('sha256').update(JSON.stringify([b.height,b.hash,b.previous_hash,b.transactions.map(t => [t.hash,t.signer,t.success])])).digest('hex');
    this.db.exec('BEGIN IMMEDIATE');
    try {
      const existing = this.db.prepare('SELECT digest FROM blocks WHERE height=?').get(b.height);
      if (existing) {
        if (existing.digest !== digest) throw new Error('Finalized history changed; stop and reconcile');
        this.db.exec('COMMIT');
        return false;
      }
      const tip = this.tip();
      if (b.height !== (tip ? tip.height + 1 : this.startHeight)) throw new Error('Noncontiguous history');
      if (tip && b.previous_hash !== tip.hash) throw new Error('Canonical parent mismatch');
      if (b.height === 0 && b.hash !== this.chainId) throw new Error('Genesis hash differs from chain id');
      this.db.prepare('INSERT INTO blocks(height,hash,previous_hash,digest) VALUES(?,?,?,?)').run(b.height,b.hash,b.previous_hash,digest);
      const insertTx = this.db.prepare('INSERT INTO transactions VALUES(?,?,?,?)');
      const insertSigner = this.db.prepare('INSERT OR IGNORE INTO first_signers VALUES(?,?)');
      for (const tx of b.transactions) {
        insertTx.run(tx.hash,b.height,tx.signer,Number(tx.success));
        if (tx.success) insertSigner.run(tx.signer,b.height);
      }
      this.db.exec('COMMIT');
      return true;
    } catch (error) {
      this.db.exec('ROLLBACK');
      if (/Finalized history changed|Canonical parent mismatch/.test(error.message)) this.quarantine();
      throw error;
    }
  }

  // Called within the archive import transaction. Times are never taken from
  // the RPC response; this trust boundary must stay explicit.
  setTime(row, digest) {
    integer(row?.height, 'time height'); integer(row.timestamp, 'timestamp');
    if (row.chain_id !== this.chainId || row.timestamp > Math.floor(Date.now()/1000)) throw new Error('Wrong chain or future timestamp');
    const block = this.db.prepare('SELECT * FROM blocks WHERE height=?').get(row.height);
    if (!block || row.hash !== block.hash) throw new Error('Archive hash does not match indexed canonical block');
    if (block.timestamp !== null && block.timestamp !== row.timestamp) throw new Error('Conflicting timestamp; rebuild after source review');
    const before = this.db.prepare('SELECT timestamp FROM blocks WHERE height<? AND timestamp IS NOT NULL ORDER BY height DESC LIMIT 1').get(row.height);
    const after = this.db.prepare('SELECT timestamp FROM blocks WHERE height>? AND timestamp IS NOT NULL ORDER BY height LIMIT 1').get(row.height);
    if ((before && before.timestamp > row.timestamp) || (after && after.timestamp < row.timestamp)) throw new Error('Nonmonotonic archive time');
    if (block.timestamp === null) this.db.prepare('UPDATE blocks SET timestamp=?,time_source=? WHERE height=?').run(row.timestamp,digest,row.height);
  }

  daily(date, now = Date.now()/1000) {
    const [start,end] = dayWindow(date);
    const base = { date, start, end, status: 'incomplete', reasons: [], blocks: null, transactions: null,
      successful_transactions: null, unique_active_addresses: null, new_addresses: null,
      new_addresses_status: 'incomplete', source: null };
    const integrity = this.db.prepare('SELECT reason FROM integrity').get();
    if (integrity) return { ...base, reasons:[integrity.reason] };
    if (end > now) return { ...base, reasons: ['utc_day_not_closed'] };
    // A known block on either side bounds the day. Indexing is contiguous;
    // every block between these anchors must have a reviewed time mapping.
    let left = this.db.prepare('SELECT * FROM blocks WHERE timestamp<? ORDER BY height DESC LIMIT 1').get(start);
    const right = this.db.prepare('SELECT * FROM blocks WHERE timestamp>=? ORDER BY height LIMIT 1').get(end);
    const genesis = this.startHeight === 0 ? this.db.prepare('SELECT timestamp FROM blocks WHERE height=0').get() : null;
    if (!left && genesis?.timestamp !== null && genesis?.timestamp >= start && genesis?.timestamp < end)
      left = {height:-1,hash:null,timestamp:null}; // No activity exists before genesis.
    if (!left || !right) return { ...base, reasons: ['missing_time_boundaries'] };
    const missing = this.db.prepare('SELECT count(*) AS n FROM blocks WHERE height BETWEEN ? AND ? AND timestamp IS NULL').get(left.height,right.height).n;
    if (missing) return { ...base, reasons: ['missing_block_times'] };
    const counts = this.db.prepare(`SELECT count(*) AS transactions, coalesce(sum(success),0) AS successful_transactions,
      count(DISTINCT CASE WHEN success=1 THEN signer END) AS unique_active_addresses
      FROM transactions WHERE height>? AND height<?`).get(left.height,right.height);
    const newCount = this.startHeight === 0
      ? this.db.prepare('SELECT count(*) AS n FROM first_signers WHERE height>? AND height<?').get(left.height,right.height).n : null;
    const sources = this.db.prepare(`SELECT DISTINCT s.digest,s.url FROM time_sources s JOIN blocks b ON s.digest=b.time_source
      WHERE b.height BETWEEN ? AND ?`).all(left.height,right.height);
    return { ...base, ...counts, status: 'complete', blocks: right.height-left.height-1, new_addresses: newCount,
      new_addresses_status: newCount === null ? 'incomplete' : 'complete',
      source: { from_height: left.height+1, to_height_exclusive: right.height,
        previous_block: left.height === -1 ? null : { height:left.height, hash:left.hash, timestamp:left.timestamp },
        next_block: { height:right.height, hash:right.hash, timestamp:right.timestamp },
        timestamp_basis:'external_archive', time_sources:sources } };
  }

  status() {
    return { schema_version:1, chain:'amadeus', chain_id:this.chainId, start_height:this.startHeight,
      indexed_tip:this.tip(), missing_block_times:this.db.prepare('SELECT count(*) AS n FROM blocks WHERE timestamp IS NULL').get().n,
      integrity:this.db.prepare('SELECT reason FROM integrity').get()?.reason ?? 'ok',
      first_signer_history_complete:this.startHeight === 0 && this.tip() !== null, methodology:METHODOLOGY };
  }
}
