import { FastMCP } from 'fastmcp';
import { registerLoadPcap } from './tools/load-pcap';
import { registerAnalyzePcap } from './tools/analyze-pcap';
import { registerQueryPcap } from './tools/query-pcap';
import { registerFollowStream } from './tools/follow-stream';
import { registerInspectPacket } from './tools/inspect-packet';
import { registerListPcaps } from './tools/list-pcaps';
import { registerListInterfaces } from './tools/list-interfaces';
import { registerStartCapture } from './tools/start-capture';
import { registerStopCapture } from './tools/stop-capture';
import { registerCaptureStatus } from './tools/capture-status';

const server = new FastMCP({
  name: 'tshark-mcp',
  version: '3.0.0',
});

registerLoadPcap(server);
registerAnalyzePcap(server);
registerQueryPcap(server);
registerFollowStream(server);
registerInspectPacket(server);
registerListPcaps(server);
registerListInterfaces(server);
registerStartCapture(server);
registerStopCapture(server);
registerCaptureStatus(server);

server.start({ transportType: 'stdio' });
