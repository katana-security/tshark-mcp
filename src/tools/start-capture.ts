import { z } from 'zod';
import type { FastMCP } from 'fastmcp';
import { spawnTshark, getSudoHint } from '../tshark';
import { validateInterfaceName, validateBpfFilter } from '../validation';
import {
  registerCapture,
  hasCapture,
  deriveUniqueCaptureLabel,
  getCapture,
} from '../state';

export function registerStartCapture(server: FastMCP): void {
  server.addTool({
    name: 'start_capture',
    description:
      'Start a live packet capture on a network interface using tshark. ' +
      'Returns a label to reference the capture in stop_capture and capture_status. ' +
      'Requires sudo on macOS/Linux.',
    parameters: z.object({
      iface: z
        .string()
        .describe('Network interface to capture on (e.g. en0, eth0, any)'),
      outputPath: z
        .string()
        .optional()
        .describe(
          'Path to save the pcapng file. Default: /tmp/tshark-mcp-capture-<label>.pcapng'
        ),
      filter: z
        .string()
        .optional()
        .describe('BPF capture filter (e.g. "port 443", "host 10.0.0.1")'),
      label: z
        .string()
        .optional()
        .describe(
          'Label for this capture. If omitted, derived from interface name.'
        ),
      maxPackets: z
        .number()
        .optional()
        .describe('Stop after capturing N packets (-c flag)'),
      duration: z
        .number()
        .optional()
        .describe('Stop after N seconds (-a duration:N)'),
    }),
    execute: async (args) => {
      validateInterfaceName(args.iface);
      validateBpfFilter(args.filter);

      const label = args.label
        ? (hasCapture(args.label)
            ? (() => { throw new Error(`Capture label "${args.label}" already in use.`); })()
            : args.label) as string
        : deriveUniqueCaptureLabel(args.iface);

      const outputPath =
        args.outputPath || `/tmp/tshark-mcp-capture-${label}.pcapng`;

      const tsharkArgs = ['-i', args.iface, '-w', outputPath];
      if (args.filter) {
        tsharkArgs.push('-f', args.filter);
      }
      if (args.maxPackets) {
        tsharkArgs.push('-c', String(args.maxPackets));
      }
      if (args.duration) {
        tsharkArgs.push('-a', `duration:${args.duration}`);
      }

      const child = await spawnTshark(tsharkArgs);

      // Wait briefly to detect immediate failures (sudo, permission, bad interface)
      const startError = await new Promise<string | null>((resolve) => {
        let stderrBuf = '';
        const onData = (chunk: Buffer) => {
          stderrBuf += chunk.toString();
        };
        child.stderr?.on('data', onData);

        const earlyExit = (code: number | null) => {
          cleanup();
          resolve(
            stderrBuf.trim() ||
              `tshark exited immediately with code ${code}`
          );
        };

        const timer = setTimeout(() => {
          cleanup();
          resolve(null); // no error within 500ms — looks good
        }, 500);

        function cleanup() {
          clearTimeout(timer);
          child.stderr?.removeListener('data', onData);
          child.removeListener('exit', earlyExit);
        }

        child.once('exit', earlyExit);
      });

      if (startError) {
        const hint =
          startError.toLowerCase().includes('password') ||
          startError.toLowerCase().includes('sudo')
            ? `\n${getSudoHint()}`
            : '';
        throw new Error(`Capture failed to start: ${startError}${hint}`);
      }

      const entry = {
        label,
        iface: args.iface,
        filter: args.filter || null,
        outputPath,
        process: child,
        startedAt: new Date(),
        status: 'running' as const,
      };

      // Update status on process exit
      child.on('exit', (code) => {
        try {
          const cap = getCapture(label);
          if (cap.status === 'running') {
            cap.status = code === 0 || code === null ? 'stopped' : 'error';
            if (cap.status === 'error') {
              cap.error = `tshark exited with code ${code}`;
            }
          }
        } catch {
          // capture may have been removed
        }
      });

      registerCapture(entry);

      const result = {
        label,
        iface: args.iface,
        outputPath,
        filter: args.filter || null,
        status: 'running',
      };

      return JSON.stringify(result, null, 2);
    },
  });
}
