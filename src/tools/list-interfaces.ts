import { z } from 'zod';
import type { FastMCP } from 'fastmcp';
import { runTshark } from '../tshark';

interface NetworkInterface {
  index: number;
  name: string;
  description: string;
}

function parseInterfaces(raw: string): NetworkInterface[] {
  const lines = raw.trim().split('\n').filter(Boolean);
  const interfaces: NetworkInterface[] = [];
  for (const line of lines) {
    const match = line.match(/^(\d+)\.\s+(\S+)(?:\s+\((.+)\))?/);
    if (match) {
      interfaces.push({
        index: parseInt(match[1], 10),
        name: match[2],
        description: match[3] || '',
      });
    }
  }
  return interfaces;
}

export function registerListInterfaces(server: FastMCP): void {
  server.addTool({
    name: 'list_interfaces',
    description:
      'List available network interfaces for live packet capture. Returns interface names that can be used with start_capture.',
    parameters: z.object({}),
    execute: async () => {
      const stdout = await runTshark(['-D'], { timeout: 10_000 });
      const interfaces = parseInterfaces(stdout);
      return JSON.stringify({ count: interfaces.length, interfaces }, null, 2);
    },
  });
}
