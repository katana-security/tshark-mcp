import * as fs from 'fs';
import { promisify } from 'util';
import { z } from 'zod';
import type { FastMCP } from 'fastmcp';
import { getCapture, getAllCaptures, CaptureEntry } from '../state';

const fsStat = promisify(fs.stat);

function formatDuration(startedAt: Date): string {
  const ms = new Date().getTime() - startedAt.getTime();
  const totalSec = Math.round(ms / 1000);
  const minutes = Math.floor(totalSec / 60);
  const seconds = totalSec % 60;
  return minutes > 0 ? `${minutes}m ${seconds}s` : `${seconds}s`;
}

async function formatEntry(entry: CaptureEntry) {
  let outputSizeMB = 0;
  try {
    const stat = await fsStat(entry.outputPath);
    outputSizeMB = parseFloat((stat.size / (1024 * 1024)).toFixed(2));
  } catch {
    // file may not exist yet
  }

  return {
    label: entry.label,
    iface: entry.iface,
    filter: entry.filter,
    outputPath: entry.outputPath,
    status: entry.status,
    startedAt: entry.startedAt.toISOString(),
    runningSince: entry.status === 'running' ? formatDuration(entry.startedAt) : null,
    outputSizeMB,
    ...(entry.error ? { error: entry.error } : {}),
  };
}

export function registerCaptureStatus(server: FastMCP): void {
  server.addTool({
    name: 'capture_status',
    description:
      'Check the status of live captures. If a label is provided, shows that specific capture. Otherwise shows all captures.',
    parameters: z.object({
      label: z
        .string()
        .optional()
        .describe(
          'Label of a specific capture to check. Omit to list all captures.'
        ),
    }),
    execute: async (args) => {
      if (args.label) {
        const entry = getCapture(args.label);
        const formatted = await formatEntry(entry);
        return JSON.stringify(formatted, null, 2);
      }

      const all = getAllCaptures();
      if (all.length === 0) {
        return JSON.stringify(
          {
            count: 0,
            captures: [],
            hint: 'No captures. Use start_capture to begin one.',
          },
          null,
          2
        );
      }

      const captures = await Promise.all(all.map(formatEntry));
      return JSON.stringify({ count: captures.length, captures }, null, 2);
    },
  });
}
