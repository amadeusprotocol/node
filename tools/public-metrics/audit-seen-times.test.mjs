import { test } from 'node:test';
import assert from 'node:assert/strict';
import { auditSeenTimes } from './audit-seen-times.mjs';
const chain_id='HsFp8cZeFuPxBmJcjvfwYu9MqXZi8fW6XxecLfyHEqEY';
const read=(times,extra={})=>async url=>url.pathname.endsWith('/status')?
  {error:'ok',schema_version:1,chain_id,rooted_height:10,pruned_below_height:0}:
  {error:'ok',schema_version:1,chain_id,block:{height:Number(url.pathname.split('/').at(-1)),hash:'abc',finalized:true,...times[Number(url.pathname.split('/').at(-1))],...extra}};
const row=t=>({node_seen_time_ms:t,node_seen_time_basis:'local_database_insertion'});
test('available monotonic samples never certify historical UTC',async()=>{
  const r=await auditSeenTimes('https://example.test',[2,1,2],read({1:row(100),2:row(200)}),1000);
  assert.equal(r.rows.length,2);assert.equal(r.diagnostic_fields_available,true);
  assert.equal(r.historical_utc_verified,false);
});
test('distinguishes absent fields, missing records, invalid and future times',async()=>{
  const r=await auditSeenTimes('https://example.test',[1,2,3,4],read({1:{},2:row(null),3:row('100'),4:row(2000)}),1000);
  assert.deepEqual(r.rows.map(r=>r.issues[0]),['field_not_deployed','time_not_stored','invalid_time','future_time']);
  assert.equal(r.diagnostic_fields_available,false);
});
test('flags reversed samples and rejects invalid finality and excessive requests',async()=>{
  const r=await auditSeenTimes('https://example.test',[1,2],read({1:row(200),2:row(100)}),1000);
  assert.equal(r.reversals.length,1);
  await assert.rejects(auditSeenTimes('https://example.test',[1],read({1:row(100)},{finalized:false})),/Invalid block/);
  await assert.rejects(auditSeenTimes('https://example.test',Array(101).fill(1),read({})),/1..100/);
});
