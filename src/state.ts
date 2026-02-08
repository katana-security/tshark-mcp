import * as path from 'path';
import { ChildProcess } from 'child_process';

export interface PcapEntry {
  label: string;
  path: string;
  sizeMB: number;
  packets: number | string;
  loadedAt: Date;
}

const pcapRegistry = new Map<string, PcapEntry>();

export function registerPcap(entry: PcapEntry): void {
  pcapRegistry.set(entry.label, entry);
}

export function getPcap(label: string): PcapEntry {
  const entry = pcapRegistry.get(label);
  if (!entry) {
    const available = [...pcapRegistry.keys()];
    const hint = available.length
      ? ` Available: ${available.join(', ')}`
      : ' No pcaps loaded. Use load_pcap first.';
    throw new Error(`No pcap with label "${label}".${hint}`);
  }
  return entry;
}

export function hasPcap(label: string): boolean {
  return pcapRegistry.has(label);
}

export function getAllPcaps(): PcapEntry[] {
  return [...pcapRegistry.values()];
}

export function removePcap(label: string): boolean {
  return pcapRegistry.delete(label);
}

export function deriveUniqueLabel(baseName: string): string {
  const stem = path.basename(baseName, path.extname(baseName));
  if (!pcapRegistry.has(stem)) return stem;
  let i = 2;
  while (pcapRegistry.has(`${stem}_${i}`)) i++;
  return `${stem}_${i}`;
}

// --- Capture Registry ---

export interface CaptureEntry {
  label: string;
  iface: string;
  filter: string | null;
  outputPath: string;
  process: ChildProcess;
  startedAt: Date;
  status: 'running' | 'stopped' | 'error';
  error?: string;
}

const captureRegistry = new Map<string, CaptureEntry>();

export function registerCapture(entry: CaptureEntry): void {
  captureRegistry.set(entry.label, entry);
}

export function getCapture(label: string): CaptureEntry {
  const entry = captureRegistry.get(label);
  if (!entry) {
    const available = [...captureRegistry.keys()];
    const hint = available.length
      ? ` Available: ${available.join(', ')}`
      : ' No active captures. Use start_capture first.';
    throw new Error(`No capture with label "${label}".${hint}`);
  }
  return entry;
}

export function hasCapture(label: string): boolean {
  return captureRegistry.has(label);
}

export function getAllCaptures(): CaptureEntry[] {
  return [...captureRegistry.values()];
}

export function removeCapture(label: string): boolean {
  return captureRegistry.delete(label);
}

export function deriveUniqueCaptureLabel(iface: string): string {
  if (!captureRegistry.has(iface)) return iface;
  let i = 2;
  while (captureRegistry.has(`${iface}_${i}`)) i++;
  return `${iface}_${i}`;
}
