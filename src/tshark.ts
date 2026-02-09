import { execFile, spawn, ChildProcess } from 'child_process';
import { promisify } from 'util';

const execFileAsync = promisify(execFile);

let cachedTsharkPath: string | null = null;

export const TSHARK_DEFAULTS = {
  maxBuffer: 50 * 1024 * 1024,
  timeout: 120_000,
};

export async function findTshark(): Promise<string> {
  if (cachedTsharkPath) return cachedTsharkPath;

  const candidates =
    process.platform === 'win32'
      ? [
          'tshark',
          'C:\\Program Files\\Wireshark\\tshark.exe',
          'C:\\Program Files (x86)\\Wireshark\\tshark.exe',
        ]
      : [
          'tshark',
          '/usr/bin/tshark',
          '/usr/local/bin/tshark',
          '/opt/homebrew/bin/tshark',
          '/Applications/Wireshark.app/Contents/MacOS/tshark',
        ];

  for (const candidate of candidates) {
    try {
      await execFileAsync(candidate, ['-v'], { timeout: 5000 });
      cachedTsharkPath = candidate;
      return candidate;
    } catch {
      // next candidate
    }
  }
  throw new Error(
    'tshark not found. Install Wireshark and ensure tshark is in your PATH.'
  );
}

export interface TsharkOptions {
  maxBuffer?: number;
  timeout?: number;
  sslKeylogFile?: string;
}

export async function runTshark(
  args: string[],
  opts: TsharkOptions = {}
): Promise<string> {
  const tshark = await findTshark();
  const { sslKeylogFile, ...execOpts } = opts;
  const merged = { ...TSHARK_DEFAULTS, ...execOpts };
  const finalArgs = sslKeylogFile
    ? ['-o', `tls.keylog_file:${sslKeylogFile}`, ...args]
    : args;
  const { stdout } = await execFileAsync(tshark, finalArgs, merged);
  return stdout;
}

export async function spawnTshark(args: string[]): Promise<ChildProcess> {
  const tshark = await findTshark();
  if (process.platform !== 'win32') {
    const child = spawn('sudo', [tshark, ...args], {
      stdio: ['ignore', 'pipe', 'pipe'],
    });
    attachSudoErrorDetection(child);
    return child;
  }
  return spawn(tshark, args, {
    stdio: ['ignore', 'pipe', 'pipe'],
  });
}

function attachSudoErrorDetection(child: ChildProcess): void {
  let stderrData = '';
  child.stderr?.on('data', (chunk: Buffer) => {
    stderrData += chunk.toString();
    if (stderrData.includes('password') || stderrData.includes('Password')) {
      child.kill('SIGKILL');
    }
  });
}

export function getSudoHint(): string {
  return (
    'sudo failed — tshark requires root for live capture. ' +
    'Configure passwordless sudo:\n' +
    "  echo '${USER} ALL=(ALL) NOPASSWD: /usr/bin/tshark' | sudo tee /etc/sudoers.d/tshark"
  );
}
