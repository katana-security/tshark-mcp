import * as fs from 'fs';
import { promisify } from 'util';
import { z } from 'zod';
import type { FastMCP } from 'fastmcp';
import { getCapture } from '../state';

const fsStat = promisify(fs.stat);

export function registerStopCapture(server: FastMCP): void {
  server.addTool({
    name: 'stop_capture',
    description:
      'Stop a running live capture by label. Sends SIGINT to tshark so it flushes remaining packets to disk. ' +
      'Use load_pcap afterwards to analyze the resulting pcapng file.',
    parameters: z.object({
      label: z.string().describe('Label of the capture to stop'),
    }),
    execute: async (args) => {
      const entry = getCapture(args.label);

      if (entry.status !== 'running') {
        throw new Error(
          `Capture "${args.label}" already ${entry.status}.`
        );
      }

      const child = entry.process;

      // Send SIGINT for graceful shutdown (tshark flushes pcap)
      child.kill('SIGINT');

      // Wait for exit with 5s timeout
      await new Promise<void>((resolve) => {
        const timer = setTimeout(() => {
          child.kill('SIGKILL');
          resolve();
        }, 5000);

        child.once('exit', () => {
          clearTimeout(timer);
          resolve();
        });
      });

      entry.status = 'stopped';

      const durationMs =
        new Date().getTime() - entry.startedAt.getTime();
      const durationSec = Math.round(durationMs / 1000);
      const minutes = Math.floor(durationSec / 60);
      const seconds = durationSec % 60;
      const durationStr = minutes > 0 ? `${minutes}m ${seconds}s` : `${seconds}s`;

      let sizeMB = 0;
      try {
        const stat = await fsStat(entry.outputPath);
        sizeMB = parseFloat((stat.size / (1024 * 1024)).toFixed(2));
      } catch {
        // file may not exist if capture was very short
      }

      const result = {
        label: args.label,
        outputPath: entry.outputPath,
        sizeMB,
        duration: durationStr,
        status: 'stopped',
      };

      return JSON.stringify(result, null, 2);
    },
  });
}
