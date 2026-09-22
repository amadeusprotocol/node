import { setTimeout as delay } from 'node:timers/promises';
import { sync } from './collector.mjs';

// A single loop owns ingestion. Retries never overlap or advance the checkpoint.
export async function collectContinuously(store, rpc, {
  signal, limit = 100, pollMs = 10000, retryMaxMs = 300000,
  state = {}, fetcher = fetch, wait = delay, log = console.log,
} = {}) {
  for (const [name,value] of Object.entries({limit,pollMs,retryMaxMs})) {
    if (!Number.isSafeInteger(value) || value < 1) throw new Error(`Invalid ${name}`);
  }
  if (limit > 10000 || retryMaxMs < pollMs) throw new Error('Invalid collector bounds');
  let failures = 0;
  const read = (url, options) => fetcher(url, {...options,
    signal: signal ? AbortSignal.any([signal,options.signal]) : options.signal});
  while (!signal?.aborted) {
    let pause = pollMs;
    try {
      const result = await sync(store,rpc,limit,read);
      failures = 0;
      Object.assign(state,{last_success:new Date().toISOString(),last_error:null,consecutive_failures:0,...result});
      log(JSON.stringify({event:'sync',...state}));
      // Yield between full batches, while catching up without a polling delay.
      if (result.next_height <= result.rooted_height) pause = 1;
    } catch (error) {
      if (signal?.aborted) break;
      failures++;
      // Integrity faults need operator reconciliation; never auto-clear them.
      if (store.db.prepare('SELECT reason FROM integrity').get()) throw error;
      pause = Math.min(retryMaxMs,pollMs * 2 ** Math.min(failures-1,20));
      Object.assign(state,{last_error:String(error.message),consecutive_failures:failures});
      log(JSON.stringify({event:'sync_failed',retry_ms:pause,...state}));
    }
    state.consecutive_failures = failures;
    try { await wait(pause,undefined,{signal}); }
    catch (error) { if (!signal?.aborted) throw error; }
  }
}
