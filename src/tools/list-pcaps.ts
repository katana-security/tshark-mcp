import { z } from 'zod';
import type { FastMCP } from 'fastmcp';
import { getAllPcaps } from '../state';

export function registerListPcaps(server: FastMCP): void {
  server.addTool({
    name: 'list_pcaps',
    description:
      'List all pcap files currently loaded in the registry with their labels, paths, sizes, packet counts, and load times.',
    parameters: z.object({}),
    execute: async () => {
      const pcaps = getAllPcaps();
      if (pcaps.length === 0) {
        return JSON.stringify({ count: 0, pcaps: [], hint: 'No pcaps loaded. Use load_pcap to load one.' }, null, 2);
      }
      const result = {
        count: pcaps.length,
        pcaps: pcaps.map((p) => ({
          label: p.label,
          path: p.path,
          sizeMB: p.sizeMB,
          packets: p.packets,
          loadedAt: p.loadedAt.toISOString(),
        })),
      };
      return JSON.stringify(result, null, 2);
    },
  });
}
