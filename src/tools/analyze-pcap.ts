import { z } from 'zod';
import type { FastMCP } from 'fastmcp';
import { runTshark } from '../tshark';
import { resolveTargetPcap, assertFileExists } from '../validation';
import { parseProtocolHierarchy } from './load-pcap';

export function registerAnalyzePcap(server: FastMCP): void {
  server.addTool({
    name: 'analyze_pcap',
    description:
      'Run a broad analysis on the specified pcap: protocol hierarchy, conversations, DNS, TLS SNI, HTTP hosts, and endpoints.',
    parameters: z.object({
      label: z.string().describe('Label of the loaded pcap to analyze'),
    }),
    execute: async (args) => {
      const resolved = resolveTargetPcap(args.label);
      await assertFileExists(resolved);

      const [
        protoHier,
        tcpConv,
        udpConv,
        dnsRaw,
        tlsSniRaw,
        tcpEndpoints,
        httpHostsRaw,
      ] = await Promise.all([
        runTshark(['-r', resolved, '-qz', 'io,phs']),
        runTshark(['-r', resolved, '-qz', 'conv,tcp']),
        runTshark(['-r', resolved, '-qz', 'conv,udp']),
        runTshark([
          '-r', resolved, '-T', 'fields', '-e', 'dns.qry.name', '-Y', 'dns.qry.name',
        ]).catch(() => ''),
        runTshark([
          '-r', resolved, '-T', 'fields',
          '-e', 'tls.handshake.extensions_server_name',
          '-Y', 'tls.handshake.type == 1',
        ]).catch(() => ''),
        runTshark(['-r', resolved, '-qz', 'endpoints,tcp']),
        runTshark([
          '-r', resolved, '-T', 'fields', '-e', 'http.host', '-Y', 'http.host',
        ]).catch(() => ''),
      ]);

      const dedup = (raw: string): string[] => [
        ...new Set(raw.trim().split('\n').filter(Boolean)),
      ];

      const result = {
        protocolHierarchy: parseProtocolHierarchy(protoHier),
        tcpConversations: tcpConv.trim(),
        udpConversations: udpConv.trim(),
        tcpEndpoints: tcpEndpoints.trim(),
        dnsQueries: dedup(dnsRaw),
        tlsSni: dedup(tlsSniRaw),
        httpHosts: dedup(httpHostsRaw),
      };

      return JSON.stringify(result, null, 2);
    },
  });
}
