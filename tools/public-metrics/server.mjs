import { createServer } from 'node:http';
import { dayWindow, METHODOLOGY } from './store.mjs';

export function createMetricsServer(store) {
  return createServer((req,res) => {
    const send = (status,data) => {
      res.writeHead(status, {'Content-Type':'application/json', 'Cache-Control':'no-store', 'Access-Control-Allow-Origin':'*', 'X-Content-Type-Options':'nosniff'});
      res.end(JSON.stringify(data));
    };
    if (req.method !== 'GET') return send(405,{ error:'method_not_allowed' });
    let url;
    try { url = new URL(req.url,'http://localhost'); }
    catch { return send(400,{ error:'invalid_request' }); }
    if (url.pathname === '/v1/metrics/status') return send(200,store.status());
    if (url.pathname === '/v1/metrics/methodology') return send(200,METHODOLOGY);
    if (url.pathname !== '/v1/metrics/daily') return send(404,{ error:'not_found' });
    let start,end;
    try {
      const keys = [...url.searchParams.keys()];
      if (keys.some(k => !['start','end'].includes(k)) || new Set(keys).size !== keys.length) throw new Error('Only start and end are supported');
      [start] = dayWindow(url.searchParams.get('start'));
      [end] = dayWindow(url.searchParams.get('end'));
      if (end <= start || end-start > 31*86400) throw new Error('Range must be 1..31 UTC days; end is exclusive');
    } catch (error) { return send(400,{error:'invalid_range',message:error.message}); }
    try {
      const days = [];
      for (let ts=start;ts<end;ts+=86400) days.push(store.daily(new Date(ts*1000).toISOString().slice(0,10)));
      send(200,{schema_version:1,chain:'amadeus',chain_id:store.chainId,methodology_version:METHODOLOGY.version,
        status:days.every(d=>d.status==='complete')?'complete':'incomplete',days});
    } catch (error) {
      console.error('Metrics query failed:',error.message);
      send(503,{error:'metrics_unavailable'});
    }
  });
}
