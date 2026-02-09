import * as fs from 'fs';
import * as path from 'path';
import { promisify } from 'util';
import { getPcap } from './state';

const fsAccess = promisify(fs.access);

const SHELL_META = /[`$;{}&|<>()!#]/;

export function validatePcapPath(rawPath: string): string {
  if (SHELL_META.test(rawPath))
    throw new Error('pcapPath contains disallowed characters.');
  return path.resolve(rawPath);
}

export function resolveTargetPcap(label: string): string {
  const entry = getPcap(label);
  return entry.path;
}

export async function assertFileExists(filePath: string): Promise<void> {
  try {
    await fsAccess(filePath, fs.constants.R_OK);
  } catch {
    throw new Error(`File not found or not readable: ${filePath}`);
  }
}

export function validateDisplayFilter(filter?: string): void {
  if (!filter) return;
  if (filter.length > 500)
    throw new Error('Display filter exceeds 500 character limit.');
  if (/[`$]/.test(filter))
    throw new Error('Display filter contains disallowed characters.');
}

export function validateFieldName(field: string): void {
  if (!/^[a-zA-Z0-9_.]+$/.test(field)) {
    throw new Error(`Invalid field name: ${field}`);
  }
}

export function validateInterfaceName(iface: string): void {
  if (!/^[a-zA-Z0-9._\-:]+$/.test(iface)) {
    throw new Error(`Invalid interface name: ${iface}`);
  }
}

export function validateKeylogPath(rawPath?: string): string | undefined {
  if (!rawPath) return undefined;
  if (SHELL_META.test(rawPath))
    throw new Error('sslKeylogFile path contains disallowed characters.');
  const resolved = path.resolve(rawPath);
  return resolved;
}

export function validateBpfFilter(filter?: string): void {
  if (!filter) return;
  if (filter.length > 500)
    throw new Error('BPF filter exceeds 500 character limit.');
  if (/[`$;{}|<>()!#]/.test(filter))
    throw new Error('BPF filter contains disallowed characters.');
}
