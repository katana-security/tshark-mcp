import * as fs from 'fs';
import { promisify } from 'util';
import { z } from 'zod';
import type { FastMCP } from 'fastmcp';
import { runTshark } from '../tshark';
import { validatePcapPath, assertFileExists, validateKeylogPath } from '../validation';
import { registerPcap, deriveUniqueLabel } from '../state';

const fsStat = promisify(fs.stat);

export interface ProtocolEntry {
  protocol: string;
  level: number;
  frames: number;
  bytes: number;
}

export function parseProtocolHierarchy(raw: string): ProtocolEntry[] {
  const lines = raw.split('\n');
  const protocols: ProtocolEntry[] = [];
  for (const line of lines) {
    const match = line.match(/^(\s*)(\S+)\s+frames:(\d+)\s+bytes:(\d+)/);
    if (!match) continue;
    const level = match[1].length / 2;
    protocols.push({
      protocol: match[2],
      level,
      frames: parseInt(match[3], 10),
      bytes: parseInt(match[4], 10),
    });
  }
  return protocols;
}

export function registerLoadPcap(server: FastMCP): void {
  server.addTool({
    name: 'load_pcap',
    description:
      'Load a pcap file into the registry for analysis. Returns file metadata, basic capture info, and the assigned label. Use the label in other tools to reference this pcap.',
    parameters: z.object({
      pcapPath: z.string().describe('Path to the pcap/pcapng file'),
      label: z.string().optional().describe('Optional label for this pcap. If omitted, derived from filename.'),
      sslKeylogFile: z.string().optional().describe('Path to SSLKEYLOGFILE for TLS decryption. If provided, all queries against this pcap will automatically decrypt TLS traffic.'),
    }),
    execute: async (args) => {
      const resolved = validatePcapPath(args.pcapPath);
      await assertFileExists(resolved);

      const keylogPath = validateKeylogPath(args.sslKeylogFile);
      if (keylogPath) await assertFileExists(keylogPath);

      const stat = await fsStat(resolved);
      const sizeMB = (stat.size / (1024 * 1024)).toFixed(2);

      const capinfos = await runTshark(
        ['-r', resolved, '-qz', 'io,phs'],
        { timeout: 30_000 }
      );

      let packetCount = 'unknown';
      try {
        const countOut = await runTshark(
          ['-r', resolved, '-T', 'fields', '-e', 'frame.number'],
          { timeout: 30_000 }
        );
        const lines = countOut.trim().split('\n').filter(Boolean);
        packetCount = lines.length.toString();
      } catch {
        // non-critical
      }

      const label = args.label || deriveUniqueLabel(resolved);
      const packets = parseInt(packetCount, 10) || packetCount;

      registerPcap({
        label,
        path: resolved,
        sizeMB: parseFloat(sizeMB),
        packets,
        loadedAt: new Date(),
        sslKeylogFile: keylogPath,
      });

      const result: Record<string, unknown> = {
        label,
        path: resolved,
        sizeMB: parseFloat(sizeMB),
        packets,
        protocolHierarchy: parseProtocolHierarchy(capinfos),
      };
      if (keylogPath) result.sslKeylogFile = keylogPath;

      return JSON.stringify(result, null, 2);
    },
  });
}
