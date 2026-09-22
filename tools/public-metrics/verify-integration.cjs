// Cross-repository integration check. All activity is a synthetic fixture.
const {test}=require('node:test');
const assert=require('node:assert/strict');
const {createRequire}=require('node:module');
const {join}=require('node:path');
const {pathToFileURL}=require('node:url');
// Sibling checkouts named node, sdk and dimension-adapters; override the parent
// explicitly when using a different workspace layout.
const root=process.env.AMADEUS_INTEGRATION_ROOT || require('node:path').resolve(__dirname,'../../..');
const {mkdtempSync,writeFileSync,rmSync}=require('node:fs');
const {tmpdir}=require('node:os');
const {createHash}=require('node:crypto');
const llamaRequire=createRequire(join(root,'dimension-adapters/package.json'));
llamaRequire('ts-node').register({transpileOnly:true,project:join(root,'dimension-adapters/tsconfig.json')});
const {parseAmadeusDay,AMADEUS_CHAIN_ID}=llamaRequire('./users/utils/amadeus.ts');
const {getAdapter,newUsers}=llamaRequire('./users/list.ts');
const runAdapter=llamaRequire('./adapters/utils/runAdapter.ts').default;
const axios=llamaRequire('axios');

test('real HTTP API -> built SDK -> DefiLlama factory and runner',async t=>{
  const {MetricsStore}=await import('./store.mjs');
  const {importTimes}=await import('./collector.mjs');
  const {createMetricsServer}=await import('./server.mjs');
  const {MetricsAPI}=await import(pathToFileURL(join(root,'sdk/dist/index.js')).href);
  const dir=mkdtempSync(join(tmpdir(),'ama-e2e-'));
  const store=new MetricsStore(join(dir,'metrics.sqlite'),{chainId:AMADEUS_CHAIN_ID});
  t.after(()=>{store.close();rmSync(dir,{recursive:true,force:true});});
  const start=Date.parse('2026-01-02T00:00:00Z')/1000;
  const txs=[[],[{hash:'Tx1',signer:'SignerA',success:true},{hash:'Tx2',signer:'SignerA',success:false}],[]];
  for(let height=0;height<3;height++)store.ingest({error:'ok',schema_version:1,chain_id:AMADEUS_CHAIN_ID,block:{
    height,hash:height===0?AMADEUS_CHAIN_ID:`B${height}`,previous_hash:height===0?'':height===1?AMADEUS_CHAIN_ID:'B1',
    finalized:true,timestamp:null,timestamp_basis:'unavailable',transaction_count:txs[height].length,transactions:txs[height],
  }});
  const content=[start-1,start,start+86400].map((timestamp,height)=>JSON.stringify({chain_id:AMADEUS_CHAIN_ID,height,hash:height===0?AMADEUS_CHAIN_ID:`B${height}`,timestamp})).join('\n');
  const file=join(dir,'times.jsonl');writeFileSync(file,content);
  await importTimes(store,file,{sourceUrl:'https://example.org/synthetic-fixture.jsonl',sha256:createHash('sha256').update(content).digest('hex')});
  const server=createMetricsServer(store);
  await new Promise(resolve=>server.listen(0,'127.0.0.1',resolve));
  t.after(()=>new Promise(resolve=>server.close(resolve)));
  const base=`http://127.0.0.1:${server.address().port}`;
  const data=await new MetricsAPI({baseUrl:base}).getDaily('2026-01-02','2026-01-03');
  assert.equal(data.days[0].unique_active_addresses,1);
  assert.equal(data.days[0].transactions,2);
  assert.equal(data.days[0].new_addresses,1);
  // Substitute only transport, preserving URL creation, parsing, factory and
  // real runner time-window behavior. No production endpoint is contacted.
  const original=axios.get;const prior=process.env.AMADEUS_METRICS_URL;
  process.env.AMADEUS_METRICS_URL='https://metrics.example.org';
  axios.get=async url=>{
    const parsed=new URL(url);assert.equal(parsed.origin,'https://metrics.example.org');
    const response=await fetch(base+parsed.pathname+parsed.search);
    return {status:response.status,data:await response.json()};
  };
  t.after(()=>{axios.get=original;if(prior===undefined)delete process.env.AMADEUS_METRICS_URL;else process.env.AMADEUS_METRICS_URL=prior;});
  const active=getAdapter('amadeus');const fresh=newUsers.getAdapter('amadeus');
  assert.ok(active.methodology.ActiveUsers);
  const a=await active.fetch({startTimestamp:start,endTimestamp:start+86400});
  assert.equal(a.dailyActiveUsers,1);assert.equal(a.dailyTransactionsCount,2);
  const n=await fresh.fetch({startTimestamp:start,endTimestamp:start+86400});assert.equal(n.dailyNewUsers,1);
  const result=await runAdapter({module:active,endTimestamp:start+86400,name:'amadeus'});
  assert.equal(result[0].dailyActiveUsers,1);
  assert.equal(result[0].dailyTransactionsCount,2);
  const newResult=await runAdapter({module:fresh,endTimestamp:start+86400,name:'amadeus'});
  assert.equal(newResult[0].dailyNewUsers,1);
  for(const mutate of [x=>x.days[0].transactions=null,x=>x.days[0].status='incomplete',x=>x.chain_id='Wrong',x=>x.days[0].start++,x=>x.days[0].unique_active_addresses=99]) {
    const invalid=structuredClone(data);mutate(invalid);assert.throws(()=>parseAmadeusDay(invalid,start,start+86400));
  }
  const invalidNew=structuredClone(data);invalidNew.days[0].new_addresses=null;invalidNew.days[0].new_addresses_status='incomplete';
  axios.get=async()=>({status:200,data:invalidNew});
  await assert.rejects(fresh.fetch({startTimestamp:start,endTimestamp:start+86400}),/first-signer/);
  axios.get=async()=>({status:503,data:{error:'metrics_unavailable'}});
  await assert.rejects(active.fetch({startTimestamp:start,endTimestamp:start+86400}));
});
