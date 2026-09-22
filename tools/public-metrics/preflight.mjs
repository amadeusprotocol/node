import { parseArgs } from 'node:util';
import { getJson } from './collector.mjs';
import { dayWindow, METHODOLOGY } from './store.mjs';

const {values} = parseArgs({options:{rpc:{type:'string'},public:{type:'string'},day:{type:'string',multiple:true}}});
const chainId='HsFp8cZeFuPxBmJcjvfwYu9MqXZi8fW6XxecLfyHEqEY';
const checks=[];
async function check(name,fn) {
  try {await fn();checks.push({name,status:'pass'});}
  catch(error) {checks.push({name,status:'fail',reason:error.message});}
}
function requireThat(condition,message) {if(!condition)throw new Error(message);}
await check('archival_rpc',async()=>{
  requireThat(!!values.rpc,'Supply --rpc with the deployed archival exporter origin');
  const base=new URL(values.rpc);
  const status=await getJson(new URL('/api/chain/metrics/status',base));
  requireThat(status.error==='ok' && status.schema_version===1 && status.chain_id===chainId,'Metrics RPC not deployed or wrong chain');
  requireThat(status.pruned_below_height===0,'Genesis archive required for new addresses');
  const first=await getJson(new URL('/api/chain/metrics/block/0',base));
  requireThat(first.block?.hash===chainId && first.block?.finalized===true,'Canonical genesis export unavailable');
});
await check('public_service',async()=>{
  requireThat(!!values.public,'Supply --public with the deployed HTTPS metrics origin');
  const base=new URL(values.public);
  requireThat(base.protocol==='https:' && !base.username && !base.password,'Public HTTPS origin required');
  const status=await getJson(new URL('/v1/metrics/status',base));
  requireThat(status.chain_id===chainId,'Public service wrong chain');
  const health=await getJson(new URL('/healthz',base));
  requireThat(health.healthy && !health.quarantined,'Collector unhealthy');
});
await check('three_complete_days',async()=>{
  const dates=[...new Set(values.day || [])];
  requireThat(dates.length>=3,'Supply --day YYYY-MM-DD for at least three independently reviewed days');
  for(const date of dates) {
    const [,end]=dayWindow(date);
    const url=new URL('/v1/metrics/daily',values.public);
    url.searchParams.set('start',date);url.searchParams.set('end',new Date(end*1000).toISOString().slice(0,10));
    const data=await getJson(url);
    requireThat(data.schema_version===1 && data.chain_id===chainId && data.methodology_version===METHODOLOGY.version && data.status==='complete',`${date}: incompatible or incomplete`);
    const row=data.days?.[0];
    requireThat(data.days.length===1 && row.date===date && row.status==='complete' && Number.isSafeInteger(row.new_addresses),`${date}: missing complete genesis coverage`);
    for(const key of ['blocks','transactions','successful_transactions','unique_active_addresses','new_addresses']) {
      requireThat(Number.isSafeInteger(row[key]) && row[key]>=0,`${date}: invalid ${key}`);
    }
    requireThat(row.new_addresses<=row.unique_active_addresses && row.unique_active_addresses<=row.successful_transactions && row.successful_transactions<=row.transactions,`${date}: inconsistent counts`);
    requireThat(row.new_addresses_status==='complete' && row.source?.timestamp_basis==='external_archive',`${date}: unsupported coverage or time basis`);
    requireThat(row.source?.time_sources?.length>0,`${date}: missing time evidence`);
  }
});
console.log(JSON.stringify({checks,ready:checks.every(c=>c.status==='pass'),
  note:'Contract checks do not replace independent replay or authenticate external timestamps.'},null,2));
if(checks.some(c=>c.status==='fail'))process.exitCode=1;
