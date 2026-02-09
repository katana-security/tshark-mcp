import { z } from 'zod';
import type { FastMCP } from 'fastmcp';
import { runTshark } from '../tshark';
import {
  resolveTargetPcap,
  assertFileExists,
  validateDisplayFilter,
  validateFieldName,
} from '../validation';
import { getKeylogForPcap } from '../state';

export function registerQueryPcap(server: FastMCP): void {
  server.addTool({
    name: 'query_pcap',
    description:
      'Run an arbitrary tshark display filter with specific field extraction on the specified pcap. The power tool for drilling into traffic iteratively.',
    parameters: z.object({
      label: z.string().describe('Label of the loaded pcap to query'),
      displayFilter: z
        .string()
        .describe(
          'Wireshark display filter (e.g. "tls.handshake.type == 1", "ip.addr == 1.2.3.4")'
        ),
      fields: z
        .array(z.string())
        .describe(
          'Tshark field names to extract (e.g. ["ip.src", "ip.dst", "tcp.port"])'
        ),
      maxPackets: z
        .number()
        .optional()
        .default(200)
        .describe('Max packets to return (default 200, max 5000)'),
      offset: z
        .number()
        .optional()
        .default(0)
        .describe('Number of matching packets to skip (default 0). Use with maxPackets for pagination.'),
    }),
    execute: async (args) => {
      const resolved = resolveTargetPcap(args.label);
      await assertFileExists(resolved);
      validateDisplayFilter(args.displayFilter);
      args.fields.forEach(validateFieldName);

      const limit = Math.min(Math.max(args.maxPackets || 200, 1), 5000);
      const offset = Math.max(args.offset || 0, 0);

      const tsharkArgs = ['-r', resolved, '-Y', args.displayFilter, '-T', 'fields'];
      for (const f of args.fields) {
        tsharkArgs.push('-e', f);
      }
      tsharkArgs.push('-E', 'separator=/t', '-E', 'quote=n');

      const stdout = await runTshark(tsharkArgs, {
        sslKeylogFile: getKeylogForPcap(args.label),
      });
      const rawLines = stdout.trim().split('\n').filter(Boolean);
      const page = rawLines.slice(offset, offset + limit);

      const packets = page.map((line) => {
        const values = line.split('\t');
        const obj: Record<string, string> = {};
        args.fields.forEach((f, i) => {
          obj[f] = values[i] || '';
        });
        return obj;
      });

      const result = {
        filter: args.displayFilter,
        fields: args.fields,
        offset,
        count: packets.length,
        total: rawLines.length,
        hasMore: offset + limit < rawLines.length,
        packets,
      };

      return JSON.stringify(result, null, 2);
    },
  });
}
