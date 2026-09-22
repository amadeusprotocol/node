import { parseArgs } from 'node:util';
import { replayWithDiskIndex } from './replay.mjs';

const {values}=parseArgs({options:{rpc:{type:'string'},public:{type:'string'},
  day:{type:'string',multiple:true},'max-blocks':{type:'string',default:'10000'}}});
if (!values.rpc || !values.public || !values.day) throw new Error('Require --rpc, --public and one or more --day');
// Disposable independent membership index, not the collector database. Full
// history is read once for all requested days; temporary storage is removed.
const result=await replayWithDiskIndex({rpc:values.rpc,publicUrl:values.public,days:values.day,
  maxBlocks:Number(values['max-blocks']),
  onProgress:progress=>console.error(JSON.stringify({event:'replay',...progress})),
});
console.log(JSON.stringify(result,null,2));
