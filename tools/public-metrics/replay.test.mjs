import test from 'node:test';
import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { spawnSync } from 'node:child_process';
import { replayDays, replayWithDiskIndex, MAINNET_CHAIN_ID } from './replay.mjs';

const chainId='Genesis', start=Date.parse('2026-01-02T00:00:00Z')/1000;
const dates=['2026-01-02','2026-01-03','2026-01-04'];
const tx=(hash,signer,success=true)=>({hash,signer,success});
function fixture() {
  const blocks=[
    [tx('TxA','SignerA')],
    [tx('TxB','SignerA'),tx('TxC','SignerC'),tx('TxD','SignerB',false)],
    [tx('TxE','SignerB'),tx('TxF','SignerC')],
    [tx('TxG','SignerA',false),tx('TxH','SignerD')],[],
  ].map((transactions,height)=>({error:'ok',schema_version:1,chain_id:chainId,block:{
    height,hash:height===0?chainId:`B${height}`,previous_hash:height===0?'':height===1?chainId:`B${height-1}`,
    finalized:true,timestamp:null,timestamp_basis:'unavailable',transactions,transaction_count:transactions.length,
  }}));
  const mappings=blocks.map(({block:b},height)=>({chain_id:chainId,height,hash:b.hash,timestamp:height===0?start-10:start+(height-1)*86400}));
  let archive=mappings.map(row=>JSON.stringify(row)).join('\n')+'\n';
  const archiveSource={url:'https://archive.example/times.jsonl',digest:createHash('sha256').update(archive).digest('hex')};
  const counts=[[3,2,2,1],[2,2,2,1],[2,1,1,1]];
  const daily=dates.map((date,i)=>({schema_version:1,chain:'amadeus',chain_id:chainId,methodology_version:'amadeus-activity-v1',status:'complete',days:[{
    date,start:start+i*86400,end:start+(i+1)*86400,status:'complete',blocks:1,
    transactions:counts[i][0],successful_transactions:counts[i][1],unique_active_addresses:counts[i][2],new_addresses:counts[i][3],new_addresses_status:'complete',
    source:{from_height:i+1,to_height_exclusive:i+2,previous_block:mappings[i],next_block:mappings[i+2],
      timestamp_basis:'external_archive',time_sources:[archiveSource]},
  }]}));
  const status={error:'ok',schema_version:1,chain_id:chainId,pruned_below_height:0,rooted_height:4};
  let finalReads=0;const requested=[];
  const f={blocks,mappings,daily,status,archiveSource,requested,mutateCheckpoint:false,
    setArchive(text,pin=false){archive=text;if(pin)archiveSource.digest=createHash('sha256').update(text).digest('hex');},
    fetcher:async url=>{
      requested.push(url.toString());
      if(url.hostname==='archive.example')return new Response(archive);
      if(url.pathname==='/v1/metrics/daily')return Response.json(daily[dates.indexOf(url.searchParams.get('start'))]);
      if(url.pathname.endsWith('/status'))return Response.json(status);
      const height=Number(url.pathname.split('/').at(-1));
      if(height===4 && ++finalReads>1 && f.mutateCheckpoint) {
        const altered=structuredClone(blocks[4]);altered.block.transactions=[tx('Changed','SignerZ')];altered.block.transaction_count=1;
        return Response.json(altered);
      }
      return Response.json(blocks[height]);
    },
  };
  f.run=options=>replayDays({rpc:'https://rpc.example',publicUrl:'https://metrics.example',days:dates,chainId,fetcher:f.fetcher,...options});
  return f;
}

test('independently replays three days, failed receipts and first-ever successful signers',async()=>{
  const f=fixture(), result=await f.run();
  assert.equal(result.status,'verified');assert.equal(result.replayed_from_height,0);
  assert.deepEqual(result.days.map(r=>r.new_addresses),[1,1,1]);
  assert.deepEqual(result.days.map(r=>r.transactions),[3,2,2]);
  assert.equal(f.requested.filter(url=>url.includes('/block/0')).length,1);
});
test('rejects altered archive bytes and wrong canonical time mappings',async()=>{
  const f=fixture();f.setArchive('changed');await assert.rejects(f.run(),/SHA-256 mismatch/);
  const g=fixture();g.mappings[1].hash='Wrong';g.setArchive(g.mappings.map(r=>JSON.stringify(r)).join('\n'),true);
  await assert.rejects(g.run(),/wrong canonical time mapping/);
});
test('detects inflated daily totals and false new-user claims',async()=>{
  const f=fixture();f.daily[0].days[0].transactions=99;
  await assert.rejects(f.run(),/transactions mismatch/);
  const g=fixture();g.daily[0].days[0].new_addresses=2;
  await assert.rejects(g.run(),/new_addresses mismatch/);
});
test('requires a genesis archive and enforces the operator block budget before downloading evidence',async()=>{
  const f=fixture();f.status.pruned_below_height=1;
  await assert.rejects(f.run(),/Unpruned canonical source/);
  const g=fixture();await assert.rejects(g.run({maxBlocks:4}),/requires 5 blocks/);
  assert.ok(!g.requested.some(url=>url.includes('archive.example')));
});
test('rejects missing times, noncontiguous blocks and changed finalized checkpoint receipts',async()=>{
  const f=fixture();f.setArchive(f.mappings.filter(r=>r.height!==1).map(r=>JSON.stringify(r)).join('\n'),true);
  await assert.rejects(f.run(),/Missing or wrong canonical time mapping/);
  const g=fixture();g.blocks[2].block.previous_hash='Wrong';await assert.rejects(g.run(),/discontinuity/);
  const h=fixture();h.mutateCheckpoint=true;await assert.rejects(h.run(),/checkpoint changed/);
});
test('disk-backed independent signer index produces the same verified counts',async()=>{
  const f=fixture();
  const actual=await replayWithDiskIndex({rpc:'https://rpc.example',publicUrl:'https://metrics.example',days:dates,chainId,fetcher:f.fetcher});
  assert.deepEqual(actual.days,(await fixture().run()).days);
});
test('each day must disclose the archive supplying its own timestamps',async()=>{
  const f=fixture(), original=f.fetcher;
  const partial=f.mappings.filter(r=>r.height!==1).map(r=>JSON.stringify(r)).join('\n');
  f.daily[0].days[0].source.time_sources=[{url:'https://archive.example/partial.jsonl',digest:createHash('sha256').update(partial).digest('hex')}];
  await assert.rejects(f.run({fetcher:async(url,options)=>url.pathname==='/partial.jsonl'?new Response(partial):original(url,options)}),/omits required timestamp provenance/);
});
test('genesis-day coverage needs no predecessor and counts initial successful signers',async()=>{
  const f=fixture();f.mappings[0].timestamp=start;
  f.setArchive(f.mappings.map(r=>JSON.stringify(r)).join('\n'),true);
  const row=f.daily[0].days[0];row.source.previous_block=null;row.source.from_height=0;
  Object.assign(row,{blocks:2,transactions:4,successful_transactions:3,new_addresses:2});
  const result=await f.run();assert.equal(result.days[0].new_addresses,2);
});
test('complete boundary evidence can verify a genuinely empty UTC day',async()=>{
  const f=fixture();f.mappings[2].timestamp=start+2*86400;
  f.setArchive(f.mappings.map(r=>JSON.stringify(r)).join('\n'),true);
  const empty=f.daily[1].days[0];empty.source.to_height_exclusive=2;empty.source.next_block=f.mappings[2];
  Object.assign(empty,{blocks:0,transactions:0,successful_transactions:0,unique_active_addresses:0,new_addresses:0});
  const next=f.daily[2].days[0];next.source.from_height=2;next.source.previous_block=f.mappings[1];
  Object.assign(next,{blocks:2,transactions:4,successful_transactions:3,unique_active_addresses:3,new_addresses:2});
  const result=await f.run();assert.equal(result.days[1].transactions,0);
});
test('release preflight cannot report ready from API claims without independent replay',()=>{
  const f=fixture();
  const responses={status:{...f.status,chain_id:MAINNET_CHAIN_ID},
    genesis:{...f.blocks[0],chain_id:MAINNET_CHAIN_ID,block:{...f.blocks[0].block,hash:MAINNET_CHAIN_ID}},
    daily:f.daily.map(row=>({...row,chain_id:MAINNET_CHAIN_ID}))};
  const code=`
    const data=${JSON.stringify(responses)};
    const dates=${JSON.stringify(dates)};
    process.argv=['node','--rpc','https://rpc.example','--public','https://metrics.example',...dates.flatMap(d=>['--day',d])];
    globalThis.fetch=async input=>{
      const url=new URL(input);
      if(url.pathname==='/api/chain/metrics/status')return Response.json(data.status);
      if(url.pathname==='/api/chain/metrics/block/0')return Response.json(data.genesis);
      if(url.pathname==='/v1/metrics/status')return Response.json({chain_id:data.status.chain_id});
      if(url.pathname==='/healthz')return Response.json({healthy:true,quarantined:false});
      if(url.pathname==='/v1/metrics/daily')return Response.json(data.daily[dates.indexOf(url.searchParams.get('start'))]);
      throw new Error('Unexpected evidence request');
    };
    await import(${JSON.stringify(new URL('./preflight.mjs',import.meta.url).href)});
  `;
  const result=spawnSync(process.execPath,['--input-type=module','-e',code],{encoding:'utf8',timeout:10000});
  assert.equal(result.status,1,result.stderr);
  assert.ok(result.stdout.trim(),result.stderr);
  const report=JSON.parse(result.stdout);
  assert.equal(report.ready,false);
  assert.deepEqual(report.checks.map(check=>check.status),['pass','pass','pass','fail']);
  assert.equal(report.checks[3].name,'independent_replay');
});
