import { MetricsStore } from './store.mjs';
import { createMetricsServer } from './server.mjs';
import { collectContinuously } from './runtime.mjs';

const env = process.env;
for (const name of ['AMA_METRICS_DB','AMA_METRICS_CHAIN_ID','AMA_METRICS_RPC']) {
  if (!env[name]) throw new Error(`Require ${name}`);
}
const port = Number(env.AMA_METRICS_PORT || 8788);
if (!Number.isInteger(port) || port < 1 || port > 65535) throw new Error('Invalid port');
const store = new MetricsStore(env.AMA_METRICS_DB,{
  chainId:env.AMA_METRICS_CHAIN_ID,startHeight:Number(env.AMA_METRICS_START_HEIGHT || 0),
});
const controller = new AbortController();
const state = {last_success:null,last_error:null};
const pollMs = Number(env.AMA_METRICS_POLL_MS || 10000);
const server = createMetricsServer(store,() => ({...state,
  healthy:!state.last_error && !!state.last_success && Date.now()-Date.parse(state.last_success) < Math.max(120000,pollMs*3),
}));
for (const signal of ['SIGINT','SIGTERM']) process.once(signal,()=>controller.abort());
try {
  await new Promise((resolve,reject)=>{
    server.once('error',reject);
    server.listen(port,env.AMA_METRICS_HOST || '127.0.0.1',resolve);
  });
  await collectContinuously(store,env.AMA_METRICS_RPC,{
    signal:controller.signal,state,pollMs,limit:Number(env.AMA_METRICS_BATCH || 100),
  });
} finally {
  controller.abort();
  await new Promise(resolve=>server.close(resolve));
  store.close();
}
