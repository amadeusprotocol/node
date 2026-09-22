import { createHash } from 'node:crypto';
import { DatabaseSync } from 'node:sqlite';
import { mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { getJson } from './collector.mjs';
import { dayWindow, integer, METHODOLOGY } from './store.mjs';

export const MAINNET_CHAIN_ID = 'HsFp8cZeFuPxBmJcjvfwYu9MqXZi8fW6XxecLfyHEqEY';
const requireThat = (condition,message) => { if (!condition) throw new Error(message); };
const validId = value => typeof value === 'string' && /^[1-9A-HJ-NP-Za-km-z]{1,100}$/.test(value);

export async function replayWithDiskIndex(options) {
  const dir=mkdtempSync(join(tmpdir(),'ama-metrics-replay-'));
  let db;
  try {
    db=new DatabaseSync(join(dir,'signers.sqlite'));
    db.exec('CREATE TABLE signers(signer TEXT PRIMARY KEY) WITHOUT ROWID');
    const lookup=db.prepare('SELECT 1 FROM signers WHERE signer=?'), add=db.prepare('INSERT OR IGNORE INTO signers VALUES(?)');
    return await replayDays({...options,seen:{has:key=>!!lookup.get(key),add:key=>add.run(key),
      begin:()=>db.exec('BEGIN'),commit:()=>db.exec('COMMIT'),rollback:()=>db.exec('ROLLBACK')}});
  } finally {db?.close();rmSync(dir,{recursive:true,force:true});}
}
function httpsOrigin(value) {
  const url = new URL(value);
  requireThat(url.protocol==='https:' && !url.username && !url.password,'Public HTTPS URL required');
  return url;
}

async function archiveBytes(url,fetcher) {
  const response = await fetcher(httpsOrigin(url),{signal:AbortSignal.timeout(30000),redirect:'error'});
  requireThat(response.ok,`Archive HTTP ${response.status}`);
  const reader = response.body.getReader(), chunks=[];
  let size=0;
  try {
    while (true) {
      const {done,value}=await reader.read();
      if (done) break;
      size+=value.length;
      requireThat(size<=64*1024*1024,'Archive exceeds 64 MiB; publish bounded files');
      chunks.push(value);
    }
    return Buffer.concat(chunks);
  } finally { await reader.cancel(); }
}

// Independent of the collector's SQL aggregation. Re-read canonical blocks
// from genesis so "new" means first successful signer, not first in a sample.
export async function replayDays({rpc,publicUrl,days,maxBlocks=10000,seen=new Set(),
  fetcher=fetch,onProgress=()=>{},chainId=MAINNET_CHAIN_ID}) {
  integer(maxBlocks,'max blocks');requireThat(maxBlocks>0,'max blocks must be positive');
  const dates=[...new Set(days)].sort();
  requireThat(dates.length>0 && dates.length<=31,'Supply 1..31 distinct days');
  const source=httpsOrigin(rpc), origin=httpsOrigin(publicUrl);
  const rows=[];
  for (const date of dates) {
    const [start,end]=dayWindow(date);
    requireThat(end<=Date.now()/1000,'UTC day has not closed');
    const url=new URL('/v1/metrics/daily',origin);
    url.searchParams.set('start',date);url.searchParams.set('end',new Date(end*1000).toISOString().slice(0,10));
    const data=await getJson(url,fetcher), row=data.days?.[0];
    requireThat(data.schema_version===1 && data.chain==='amadeus' && data.chain_id===chainId &&
      data.methodology_version===METHODOLOGY.version && data.status==='complete' && data.days?.length===1,
      `${date}: incompatible or incomplete API response`);
    requireThat(row.date===date && row.start===start && row.end===end && row.status==='complete' &&
      row.new_addresses_status==='complete' && row.source?.timestamp_basis==='external_archive',`${date}: incomplete coverage`);
    for (const key of ['blocks','transactions','successful_transactions','unique_active_addresses','new_addresses']) integer(row[key],key);
    const {from_height:from,to_height_exclusive:to,previous_block:left,next_block:right,time_sources:archives}=row.source;
    integer(from,'from height');integer(to,'to height');
    requireThat(to>=from && right?.height===to && (from===0 ? left===null : left?.height===from-1),`${date}: invalid boundary heights`);
    requireThat(validId(right.hash) && Number.isSafeInteger(right.timestamp) && right.timestamp>=end &&
      (left===null || (validId(left.hash) && Number.isSafeInteger(left.timestamp) && left.timestamp<start)),`${date}: invalid boundary times`);
    requireThat(Array.isArray(archives) && archives.length>0 && archives.length<=128,`${date}: invalid time sources`);
    rows.push({row,from,to,left,right,active:new Set(),counts:{blocks:0,transactions:0,successful_transactions:0,new_addresses:0}});
  }
  const last=Math.max(...rows.map(r=>r.to));
  requireThat(last<maxBlocks,`Genesis replay requires ${last+1} blocks; exceeds --max-blocks ${maxBlocks}`);
  const status=await getJson(new URL('/api/chain/metrics/status',source),fetcher);
  requireThat(status.error==='ok' && status.schema_version===1 && status.chain_id===chainId &&
    status.pruned_below_height===0 && Number.isSafeInteger(status.rooted_height) && status.rooted_height>=last,
    'Unpruned canonical source through the final boundary is required');

  const sources=new Map(), times=new Map();
  for (const {row} of rows) for (const item of row.source.time_sources) {
    requireThat(typeof item.digest==='string' && /^[a-f0-9]{64}$/.test(item.digest),'Invalid archive digest');
    httpsOrigin(item.url);
    const key=JSON.stringify([item.digest,item.url]);sources.set(key,item);
  }
  requireThat(sources.size<=128,'Too many archive files');
  for (const {digest,url} of sources.values()) {
    const bytes=await archiveBytes(url,fetcher);
    requireThat(createHash('sha256').update(bytes).digest('hex')===digest,'Published archive SHA-256 mismatch');
    for (const line of bytes.toString('utf8').split(/\r?\n/)) {
      if (!line.trim()) continue;
      const item=JSON.parse(line);
      integer(item.height,'archive height');integer(item.timestamp,'archive time');
      requireThat(item.chain_id===chainId && validId(item.hash) && item.timestamp<=Date.now()/1000,'Invalid archive row');
      if (!rows.some(r=>item.height>=Math.max(0,r.from-1) && item.height<=r.to)) continue;
      const saved=times.get(item.height);
      requireThat(!saved || (saved.hash===item.hash && saved.timestamp===item.timestamp),'Conflicting archive mappings');
      const keys=saved?.sourceKeys ?? new Set();keys.add(JSON.stringify([digest,url]));
      times.set(item.height,{...item,sourceKeys:keys});
    }
  }
  let previous=null, previousTime=null, lastFingerprint=null;
  const fingerprint = block => createHash('sha256').update(JSON.stringify([
    block.height,block.hash,block.previous_hash,block.finalized,block.timestamp,block.timestamp_basis,
    block.transaction_count,block.transactions?.map(tx=>[tx.hash,tx.signer,tx.success]),
  ])).digest('hex');
  for (let height=0;height<=last;height++) {
    const data=await getJson(new URL(`/api/chain/metrics/block/${height}`,source),fetcher), b=data.block;
    requireThat(data.error==='ok' && data.schema_version===1 && data.chain_id===chainId && b?.height===height &&
      b.finalized===true && b.timestamp===null && b.timestamp_basis==='unavailable' && validId(b.hash),`Invalid canonical block ${height}`);
    requireThat(height===0 ? b.hash===chainId && b.previous_hash==='' : b.previous_hash===previous,`Canonical chain discontinuity at ${height}`);
    requireThat(Array.isArray(b.transactions) && b.transaction_count===b.transactions.length,`Incomplete block ${height}`);
    const relevant=rows.filter(r=>height>=Math.max(0,r.from-1) && height<=r.to);
    if (relevant.length) {
      const time=times.get(height);
      requireThat(time?.hash===b.hash,`Missing or wrong canonical time mapping at ${height}`);
      requireThat(previousTime===null || time.timestamp>=previousTime,'Nonmonotonic archive times');
      previousTime=time.timestamp;
      for (const r of relevant) {
        requireThat(r.row.source.time_sources.some(item=>time.sourceKeys.has(JSON.stringify([item.digest,item.url]))),'Day omits required timestamp provenance');
        const anchor=height===r.to ? r.right : height===r.from-1 ? r.left : null;
        if (anchor) requireThat(anchor.hash===b.hash && anchor.timestamp===time.timestamp,'Published anchor differs from source evidence');
        else requireThat(time.timestamp>=r.row.start && time.timestamp<r.row.end,`Block ${height} lies outside ${r.row.date}`);
      }
    }
    const counting=rows.filter(r=>height>=r.from && height<r.to), txIds=new Set();
    for (const r of counting) r.counts.blocks++;
    seen.begin?.();
    try {
      for (const tx of b.transactions) {
        requireThat(validId(tx.hash) && validId(tx.signer) && typeof tx.success==='boolean' && !txIds.has(tx.hash),`Invalid receipt in block ${height}`);
        txIds.add(tx.hash);
        const isNew=tx.success && !seen.has(tx.signer);
        for (const r of counting) {
          r.counts.transactions++;
          if (tx.success) {
            r.counts.successful_transactions++;r.active.add(tx.signer);
            if (isNew) r.counts.new_addresses++;
          }
        }
        if (tx.success) seen.add(tx.signer);
      }
      seen.commit?.();
    } catch (error) {seen.rollback?.();throw error;}
    previous=b.hash;
    lastFingerprint=fingerprint(b);
    if (height%1000===0 || height===last) onProgress({height,through_height:last});
  }
  const checkpoint=await getJson(new URL(`/api/chain/metrics/block/${last}`,source),fetcher);
  requireThat(checkpoint.error==='ok' && checkpoint.schema_version===1 && checkpoint.chain_id===chainId &&
    checkpoint.block?.height===last && checkpoint.block?.hash===previous && checkpoint.block?.finalized===true &&
    fingerprint(checkpoint.block)===lastFingerprint,'Finalized checkpoint changed during replay');
  const verified=rows.map(({row,counts,active})=>{
    const actual={...counts,unique_active_addresses:active.size};
    for (const [key,value] of Object.entries(actual)) requireThat(row[key]===value,`${row.date}: ${key} mismatch: API ${row[key]}, replay ${value}`);
    return {date:row.date,...actual};
  });
  return {status:'verified',chain_id:chainId,replayed_from_height:0,replayed_through_height:last,
    days:verified,time_sources:[...sources.values()],
    time_caveat:'Archive bytes and block mappings verified; UTC assertions remain external and require methodology review.'};
}
