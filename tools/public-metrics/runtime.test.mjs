import test from 'node:test';
import assert from 'node:assert/strict';
import { MetricsStore } from './store.mjs';
import { collectContinuously } from './runtime.mjs';
import { createMetricsServer } from './server.mjs';

const genesis = {error:'ok',schema_version:1,chain_id:'Genesis',block:{
  height:0,hash:'Genesis',previous_hash:'',finalized:true,timestamp:null,
  timestamp_basis:'unavailable',transaction_count:0,transactions:[],
}};
const status = {error:'ok',schema_version:1,chain_id:'Genesis',rooted_height:0,pruned_below_height:0};
function fixture(t) {
  const store = new MetricsStore(':memory:',{chainId:'Genesis'});
  t.after(()=>store.close());
  return store;
}

test('transient outages back off serially and recover without skipping genesis',async t=>{
  const store=fixture(t), controller=new AbortController(), state={}, pauses=[];
  let calls=0, active=0, maximum=0;
  await collectContinuously(store,'http://localhost',{
    signal:controller.signal,state,pollMs:10,retryMaxMs:20,log:()=>{},
    fetcher:async url=>{
      maximum=Math.max(maximum,++active);
      try {
        if (++calls<=2) throw new Error('temporary outage');
        return Response.json(url.pathname.endsWith('status')?status:genesis);
      } finally {active--;}
    },
    wait:async ms=>{pauses.push(ms);if(pauses.length===3)controller.abort();},
  });
  assert.deepEqual(pauses,[10,20,10]);
  assert.equal(maximum,1);assert.equal(store.tip().height,0);
  assert.equal(state.last_error,null);assert.equal(state.consecutive_failures,0);
});

test('finalized checkpoint conflict terminates the collector and keeps quarantine',async t=>{
  const store=fixture(t);store.ingest(genesis);
  await assert.rejects(collectContinuously(store,'http://localhost',{
    log:()=>{},fetcher:async url=>Response.json(url.pathname.endsWith('status')?status:{
      ...genesis,block:{...genesis.block,hash:'Changed'},
    }),wait:async()=>assert.fail('must not retry a quarantined index'),
  }),/Finalized history changed/);
  assert.ok(store.db.prepare('SELECT reason FROM integrity').get());
});

test('shutdown aborts an in-flight request',async t=>{
  const store=fixture(t),controller=new AbortController();
  await collectContinuously(store,'http://localhost',{
    signal:controller.signal,log:()=>{},fetcher:async (_url,{signal})=>{
      controller.abort();signal.throwIfAborted();
    },wait:async()=>assert.fail('must not sleep after shutdown'),
  });
  assert.equal(store.tip(),null);
});

test('health reports source failure and quarantine independently of API availability',async t=>{
  const store=fixture(t);let healthy=false;
  const server=createMetricsServer(store,()=>({healthy}));
  await new Promise(resolve=>server.listen(0,'127.0.0.1',resolve));
  t.after(()=>new Promise(resolve=>server.close(resolve)));
  const url=`http://127.0.0.1:${server.address().port}`;
  assert.equal((await fetch(url+'/healthz')).status,503);
  healthy=true;assert.equal((await fetch(url+'/healthz')).status,200);
  store.quarantine();assert.equal((await fetch(url+'/healthz')).status,503);
  assert.equal((await fetch(url+'/v1/metrics/status')).status,200);
});
