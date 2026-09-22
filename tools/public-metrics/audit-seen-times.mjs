import { parseArgs } from 'node:util';
import { pathToFileURL } from 'node:url';
import { getJson } from './collector.mjs';

const chainId = 'HsFp8cZeFuPxBmJcjvfwYu9MqXZi8fW6XxecLfyHEqEY';
export async function auditSeenTimes(rpc, heights, read = getJson, now = Date.now()) {
  const base = new URL(rpc);
  if (!['https:', 'http:'].includes(base.protocol) || base.username || base.password)
    throw Error('Invalid RPC origin');
  if (!Array.isArray(heights) || !heights.length || heights.length > 100 ||
      heights.some(h => !Number.isSafeInteger(h) || h < 0)) throw Error('Require 1..100 nonnegative safe heights');
  heights = [...new Set(heights)].sort((a,b)=>a-b);
  const status = await read(new URL('/api/chain/metrics/status',base));
  if (status.error !== 'ok' || status.schema_version !== 1 || status.chain_id !== chainId ||
      !Number.isSafeInteger(status.rooted_height) || !Number.isSafeInteger(status.pruned_below_height) ||
      status.pruned_below_height < 0 || status.rooted_height < status.pruned_below_height)
    throw Error('Invalid mainnet exporter status');
  const rows = [];
  for (const height of heights) {
    if (height < status.pruned_below_height || height > status.rooted_height) throw Error('Requested height outside retained finalized history');
    const data = await read(new URL(`/api/chain/metrics/block/${height}`,base));
    const b = data.block;
    if (data.error !== 'ok' || data.schema_version !== 1 || data.chain_id !== chainId ||
        b?.height !== height || b.finalized !== true || typeof b.hash !== 'string' || !b.hash ||
        (height === 0 && b.hash !== chainId)) throw Error(`Invalid block at ${height}`);
    const present = Object.hasOwn(b,'node_seen_time_ms');
    const value = b.node_seen_time_ms;
    const issues = [];
    if (!present) issues.push('field_not_deployed');
    else if (value === null) issues.push('time_not_stored');
    else if (!Number.isSafeInteger(value) || value < 0 || value > 8640000000000000) issues.push('invalid_time');
    else if (value > now) issues.push('future_time');
    if (present && b.node_seen_time_basis !== 'local_database_insertion') issues.push('unsupported_basis');
    rows.push({height,hash:b.hash,node_seen_time_ms:value ?? null,field_present:present,issues});
  }
  const comparable = rows.filter(r=>!r.issues.length);
  const reversals = [];
  for (let i=1;i<comparable.length;i++) {
    const a=comparable[i-1], b=comparable[i];
    if (b.node_seen_time_ms<a.node_seen_time_ms) reversals.push({from_height:a.height,to_height:b.height});
  }
  // A successful sample is never certification of the original observation time.
  return {schema_version:1,rpc:base.origin,chain_id:chainId,checked_at:new Date(now).toISOString(),
    rooted_height:status.rooted_height,rows,reversals,
    diagnostic_fields_available:rows.every(r=>!r.issues.length),historical_utc_verified:false,
    note:'Sampled local insertion times only. Original archive provenance, sync/rebuild history and complete coverage require review. No timestamps imported.'};
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  const {values} = parseArgs({options:{rpc:{type:'string'},height:{type:'string',multiple:true}}});
  if (!values.rpc || !values.height?.every(h=>/^\d+$/.test(h))) throw Error('Require --rpc and repeated --height integers');
  const report = await auditSeenTimes(values.rpc,values.height.map(Number));
  console.log(JSON.stringify(report,null,2));
  if (!report.diagnostic_fields_available || report.reversals.length) process.exitCode=1;
}
