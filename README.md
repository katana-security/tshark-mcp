# tshark-mcp

MCP server for offline pcap/pcapng file analysis via tshark. Provides network traffic analysis tools that can be used by any MCP-compatible client (Claude Desktop, Cursor, Claude Code, etc.).

**This is an offline analysis tool** — it reads existing capture files, it does not perform live packet capture.

## Prerequisites

- **Node.js** >= 18.0.0
- **tshark** (part of [Wireshark](https://www.wireshark.org/download.html)) installed and accessible in your PATH

## Installation

```bash
cd tshark-mcp
npm install
npm run build
```

## Tools

### `load_pcap`

Set the active pcap file for analysis. Returns file metadata (size, packet count, protocol hierarchy). All other tools operate on this file.

| Parameter  | Type   | Required | Description                    |
|-----------|--------|----------|-------------------------------- |
| `pcapPath` | string | yes      | Path to the pcap/pcapng file   |

### `analyze_pcap`

Run a broad analysis on the active pcap: protocol hierarchy, TCP/UDP conversations, DNS queries, TLS SNI, HTTP hosts, and TCP endpoints. All 7 analyses run in parallel.

No parameters — operates on the pcap loaded via `load_pcap`.

### `query_pcap`

Run an arbitrary tshark display filter with specific field extraction. Supports pagination for large result sets.

| Parameter       | Type     | Required | Description                                                      |
|----------------|----------|----------|------------------------------------------------------------------ |
| `displayFilter` | string   | yes      | Wireshark display filter (e.g. `tls.handshake.type == 1`)        |
| `fields`        | string[] | yes      | Tshark field names to extract (e.g. `["ip.src", "ip.dst"]`)      |
| `maxPackets`    | number   | no       | Max packets per page (default 200, max 5000)                     |
| `offset`        | number   | no       | Packets to skip for pagination (default 0)                       |

### `inspect_packet`

Get the full protocol dissection of one or more packets by frame number. Returns the complete tshark JSON output with all layers and fields.

| Parameter     | Type   | Required | Description                                                       |
|--------------|--------|----------|------------------------------------------------------------------- |
| `frameNumber` | number | yes      | Frame number to inspect (e.g. 3)                                  |
| `count`       | number | no       | Consecutive frames to inspect starting from frameNumber (default 1, max 20) |

### `follow_stream`

Reconstruct and display the payload of a TCP, UDP, or TLS stream by its index. Equivalent to Wireshark's "Follow Stream" feature.

| Parameter     | Type   | Required | Description                                         |
|--------------|--------|----------|----------------------------------------------------- |
| `protocol`    | string | no       | Stream protocol: `tcp`, `udp`, or `tls` (default: `tcp`) |
| `streamIndex` | number | yes      | Stream index number (from analyze_pcap conversations) |
| `maxBytes`    | number | no       | Max bytes to return (default 32KB, max 1MB)         |

## Configuration

### Claude Code

```bash
claude mcp add tshark-mcp node /absolute/path/to/tshark-mcp/dist/index.js
```

### Claude Desktop / Cursor

```json
{
  "mcpServers": {
    "tshark-mcp": {
      "command": "node",
      "args": ["/absolute/path/to/tshark-mcp/dist/index.js"]
    }
  }
}
```

## Usage Example

1. **Load**: call `load_pcap` with the path to your capture file
2. **Overview**: call `analyze_pcap` to see protocol hierarchy, conversations, DNS queries, etc.
3. **Filter**: use `query_pcap` with display filters to extract specific fields (paginate with `offset`)
4. **Inspect**: use `inspect_packet` to get the full dissection of specific packets
5. **Streams**: use `follow_stream` to reconstruct TCP/UDP/TLS stream payloads

## License

MIT
