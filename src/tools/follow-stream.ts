import { z } from 'zod';
import type { FastMCP } from 'fastmcp';
import { runTshark } from '../tshark';
import { resolveTargetPcap, assertFileExists } from '../validation';
import { getKeylogForPcap } from '../state';

export function registerFollowStream(server: FastMCP): void {
  server.addTool({
    name: 'follow_stream',
    description:
      'Reconstruct and display the payload of a TCP, UDP, or TLS stream by its index from the specified pcap.',
    parameters: z.object({
      label: z.string().describe('Label of the loaded pcap to follow stream from'),
      protocol: z
        .enum(['tcp', 'udp', 'tls'])
        .optional()
        .default('tcp')
        .describe('Stream protocol (default: tcp)'),
      streamIndex: z
        .number()
        .describe('Stream index number (from conversation analysis or tshark)'),
      maxBytes: z
        .number()
        .optional()
        .default(32768)
        .describe('Max bytes to return (default 32KB)'),
    }),
    execute: async (args) => {
      const resolved = resolveTargetPcap(args.label);
      await assertFileExists(resolved);

      const limit = Math.min(args.maxBytes || 32768, 1024 * 1024);
      const followType = args.protocol || 'tcp';

      const stdout = await runTshark(
        ['-r', resolved, '-qz', `follow,${followType},ascii,${args.streamIndex}`],
        { timeout: 60_000, sslKeylogFile: getKeylogForPcap(args.label) }
      );

      let output = stdout;
      if (output.length > limit) {
        output = output.slice(0, limit) + `\n\n[truncated at ${limit} bytes]`;
      }

      return [
        `Stream: ${followType} #${args.streamIndex}`,
        `Size: ${stdout.length} bytes${stdout.length > limit ? ` (truncated to ${limit})` : ''}`,
        '',
        output,
      ].join('\n');
    },
  });
}
