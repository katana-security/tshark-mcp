import { z } from 'zod';
import type { FastMCP } from 'fastmcp';
import { runTshark } from '../tshark';
import { resolveTargetPcap, assertFileExists } from '../validation';

export function registerInspectPacket(server: FastMCP): void {
  server.addTool({
    name: 'inspect_packet',
    description:
      'Get the full protocol dissection of one or more packets by frame number. Returns all layers and fields as JSON.',
    parameters: z.object({
      label: z.string().describe('Label of the loaded pcap to inspect'),
      frameNumber: z
        .number()
        .describe('Frame number to inspect (e.g. 3)'),
      count: z
        .number()
        .optional()
        .default(1)
        .describe('Number of consecutive frames to inspect starting from frameNumber (default 1, max 20)'),
    }),
    execute: async (args) => {
      const resolved = resolveTargetPcap(args.label);
      await assertFileExists(resolved);

      const count = Math.min(Math.max(args.count || 1, 1), 20);
      const end = args.frameNumber + count - 1;

      const filter = count === 1
        ? `frame.number == ${args.frameNumber}`
        : `frame.number >= ${args.frameNumber} && frame.number <= ${end}`;

      const stdout = await runTshark(
        ['-r', resolved, '-Y', filter, '-T', 'json'],
        { timeout: 30_000 }
      );

      return stdout;
    },
  });
}
