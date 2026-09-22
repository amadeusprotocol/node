import { parseArgs } from 'node:util';
import { MetricsStore } from './store.mjs';
import { sync, importTimes } from './collector.mjs';
import { createMetricsServer } from './server.mjs';

const {values,positionals} = parseArgs({allowPositionals:true,options:{
  db:{type:'string'},'chain-id':{type:'string'},'start-height':{type:'string',default:'0'},
  rpc:{type:'string'},limit:{type:'string',default:'100'},file:{type:'string'},
  source:{type:'string'},sha256:{type:'string'},host:{type:'string',default:'127.0.0.1'},port:{type:'string',default:'8788'},
}});
if (!values.db || !values['chain-id']) throw new Error('Require --db and --chain-id');
const store = new MetricsStore(values.db,{chainId:values['chain-id'],startHeight:Number(values['start-height'])});
try {
  switch(positionals[0]) {
    case 'sync': console.log(JSON.stringify(await sync(store,values.rpc,Number(values.limit)))); break;
    case 'import-times': console.log(JSON.stringify(await importTimes(store,values.file,{sourceUrl:values.source,sha256:values.sha256}))); break;
    case 'status': console.log(JSON.stringify(store.status(),null,2)); break;
    case 'serve': {
      const port = Number(values.port);
      if (!Number.isInteger(port) || port<1 || port>65535) throw new Error('Invalid port');
      const server = createMetricsServer(store);
      await new Promise((resolve,reject)=>{server.once('error',reject);server.listen(port,values.host,resolve);});
      console.log(`Public metrics listening on ${values.host}:${port}`);
      await new Promise(resolve=>{
        for(const signal of ['SIGINT','SIGTERM']) process.once(signal,()=>server.close(resolve));
      });
      break;
    }
    default: throw new Error('Command must be sync, import-times, status or serve');
  }
} finally {store.close();}
