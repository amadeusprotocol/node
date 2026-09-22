import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { createHash } from 'node:crypto';
import { MetricsStore, dayWindow } from './store.mjs';
import { sync, importTimes } from './collector.mjs';
import { createMetricsServer } from './server.mjs';

const chainId='Genesis';
const start=Date.parse('2026-01-02T00:00:00Z')/1000;
export const block=(height,transactions=[])=>({error:'ok',schema_version:1,chain_id:chainId,block:{
  height,hash:height===0?chainId:`B${height}`,previous_hash:height===1?chainId:height===0?'':`B${height-1}`,
  finalized:true,timestamp:null,timestamp_basis:'unavailable',transaction_count:transactions.length,transactions,
}});
const tx=(hash,signer='SignerA',success=true)=>({hash,signer,success});
function fixture(t,startHeight=0) {
  const dir=mkdtempSync(join(tmpdir(),'ama-metrics-'));
  const store=new MetricsStore(join(dir,'metrics.sqlite'),{chainId,startHeight});
  t.after(()=>{store.close();rmSync(dir,{recursive:true,force:true});});
  return {store,dir};
}
async function times(store,dir,rows,shaOverride) {
  const content=rows.map(([height,timestamp])=>JSON.stringify({chain_id:chainId,height,hash:height===0?chainId:`B${height}`,timestamp})).join('\n')+'\n';
  const file=join(dir,'times.jsonl');writeFileSync(file,content);
  const sha256=shaOverride??createHash('sha256').update(content).digest('hex');
  return importTimes(store,file,{sourceUrl:'https://example.org/archive.jsonl',sha256});
}

test('UTC boundaries, failed transactions, distinct signers and first successful use',async t=>{
  const {store,dir}=fixture(t);
  store.ingest(block(0,[tx('Tx1')]));
  store.ingest(block(1,[tx('Tx2'),tx('Tx3'),tx('Tx4','SignerB'),tx('Tx5','SignerC',false)]));
  store.ingest(block(2,[tx('Tx6','SignerB')]));
  store.ingest(block(3,[tx('Tx7','SignerC')]));
  await times(store,dir,[[0,start-1],[1,start],[2,start+86399],[3,start+86400]]);
  const row=store.daily('2026-01-02');
  assert.equal(row.status,'complete');assert.equal(row.transactions,5);
  assert.equal(row.successful_transactions,4);assert.equal(row.unique_active_addresses,2);
  assert.equal(row.new_addresses,1);assert.equal(row.blocks,2);
  assert.equal(row.source.to_height_exclusive,3);
  assert.equal(row.source.time_sources.length,1);
});

test('replays are idempotent; conflicting roots, gaps and parents fail atomically',t=>{
  const {store}=fixture(t); const b=block(0,[tx('Tx1')]);
  assert.equal(store.ingest(b),true); assert.equal(store.ingest(b),false);
  assert.throws(()=>store.ingest(block(2)),/Noncontiguous/);
  const wrong=block(1);wrong.block.previous_hash='Wrong';
  assert.throws(()=>store.ingest(wrong),/parent mismatch/);
  assert.deepEqual({...store.tip()},{height:0,hash:chainId});
  assert.deepEqual(store.daily('2026-01-02').reasons,['source_history_conflict']);
  assert.throws(()=>store.ingest(block(1)),/quarantined/);
});

test('changed finalized history quarantines previously publishable days',async t=>{
  const {store,dir}=fixture(t);store.ingest(block(0));store.ingest(block(1));
  await times(store,dir,[[0,start],[1,start+86400]]);
  assert.equal(store.daily('2026-01-02').status,'complete');
  assert.throws(()=>store.ingest(block(0,[tx('Tx2')])),/history changed/);
  assert.equal(store.daily('2026-01-02').transactions,null);
});

test('genesis day needs no nonexistent predecessor, but still needs the next-day boundary',async t=>{
  const {store,dir}=fixture(t);store.ingest(block(0,[tx('Tx1')]));store.ingest(block(1));
  await times(store,dir,[[0,start+1],[1,start+86400]]);
  const row=store.daily('2026-01-02');
  assert.equal(row.transactions,1);assert.equal(row.new_addresses,1);
  assert.equal(row.source.previous_block,null);
});

test('duplicate transactions within/across blocks roll back blocks and signers',t=>{
  const {store}=fixture(t);store.ingest(block(0,[tx('Tx1')]));
  assert.throws(()=>store.ingest(block(1,[tx('Tx2'),tx('Tx2')])),/duplicate/);
  assert.throws(()=>store.ingest(block(1,[tx('Tx3','SignerB'),tx('Tx1')])),/UNIQUE/);
  assert.equal(store.tip().height,0);
  assert.equal(store.db.prepare('SELECT count(*) AS n FROM first_signers').get().n,1);
});

test('unknown receipts, wrong networks, unfinalized data and inferred time are rejected',t=>{
  const {store}=fixture(t);
  for(const mutate of [b=>b.chain_id='Other',b=>b.block.finalized=false,b=>b.block.timestamp=start,
    b=>b.block.transactions[0].success=null,b=>b.block.transaction_count=2]) {
    const b=block(0,[tx('Tx1')]);mutate(b);assert.throws(()=>store.ingest(b));
  }
  assert.equal(store.tip(),null);
});

test('missing times and incomplete days never become zero activity',async t=>{
  const {store,dir}=fixture(t);
  for(let i=0;i<4;i++) store.ingest(block(i));
  assert.equal(store.daily('2026-01-02').transactions,null);
  await times(store,dir,[[0,start-1],[3,start+86400]]);
  assert.deepEqual(store.daily('2026-01-02').reasons,['missing_block_times']);
  assert.deepEqual(store.daily('2026-01-02',start+1).reasons,['utc_day_not_closed']);
  await times(store,dir,[[1,start],[2,start+1]]);
  assert.equal(store.daily('2026-01-02').transactions,0);
});

test('partial archive can report activity but cannot claim globally new addresses',async t=>{
  const {store,dir}=fixture(t,5);
  store.ingest(block(5));store.ingest(block(6,[tx('Tx1')]));store.ingest(block(7));
  await times(store,dir,[[5,start-1],[6,start],[7,start+86400]]);
  const row=store.daily('2026-01-02');
  assert.equal(row.status,'complete');assert.equal(row.unique_active_addresses,1);
  assert.equal(row.new_addresses,null);assert.equal(row.new_addresses_status,'incomplete');
});

test('archive pin mismatch and nonmonotonic mappings roll back all timestamps',async t=>{
  const {store,dir}=fixture(t);store.ingest(block(0));store.ingest(block(1));
  await assert.rejects(times(store,dir,[[0,start]],'0'.repeat(64)),/SHA-256/);
  assert.equal(store.status().missing_block_times,2);
  await assert.rejects(times(store,dir,[[0,start],[1,start-1]]),/Nonmonotonic/);
  assert.equal(store.status().missing_block_times,2);
  await times(store,dir,[[0,start]]);
  await assert.rejects(times(store,dir,[[0,start+1]]),/Conflicting/);
});

test('persisted checkpoint and config survive reopening',t=>{
  const {store,dir}=fixture(t);store.ingest(block(0));
  const second=new MetricsStore(join(dir,'metrics.sqlite'),{chainId});
  assert.equal(second.tip().height,0);second.close();
  assert.throws(()=>new MetricsStore(join(dir,'metrics.sqlite'),{chainId:'Wrong'}),/another chain/);
});

test('collector validates checkpoints and resumes after an interrupted batch',async t=>{
  const {store}=fixture(t);let fail=true;
  const fetcher=async url=>{
    const path=new URL(url).pathname;
    if(path.endsWith('status'))return Response.json({error:'ok',schema_version:1,chain_id:chainId,rooted_height:2,pruned_below_height:0});
    const height=Number(path.split('/').pop());
    if(height===1&&fail)throw new Error('connection lost');
    return Response.json(block(height));
  };
  await assert.rejects(sync(store,'https://example.org',10,fetcher),/connection lost/);
  assert.equal(store.tip().height,0);fail=false;
  assert.equal((await sync(store,'https://example.org',10,fetcher)).indexed,2);
  assert.equal((await sync(store,'https://example.org',10,fetcher)).indexed,0);
});

test('public API has bounded exclusive ranges, explicit incomplete rows and no writes',async t=>{
  const {store}=fixture(t);const server=createMetricsServer(store);
  await new Promise(resolve=>server.listen(0,'127.0.0.1',resolve));
  t.after(()=>new Promise(resolve=>server.close(resolve)));
  const url=`http://127.0.0.1:${server.address().port}`;
  const data=await (await fetch(`${url}/v1/metrics/daily?start=2026-01-02&end=2026-01-03`)).json();
  assert.equal(data.days.length,1);assert.equal(data.status,'incomplete');assert.equal(data.days[0].transactions,null);
  for(const query of ['start=2026-02-30&end=2026-03-03','start=2026-01-01&end=2026-03-01','start=2026-01-01&start=2026-01-02&end=2026-01-03'])
    assert.equal((await fetch(`${url}/v1/metrics/daily?${query}`)).status,400);
  assert.equal((await fetch(`${url}/v1/metrics/status`,{method:'POST'})).status,405);
  assert.throws(()=>dayWindow('2026-02-30'));
});
