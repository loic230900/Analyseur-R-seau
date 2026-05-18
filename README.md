# Network Packet Analyzer

A network packet analyzer in C using **libpcap**. Supports both live capture on a network interface and offline analysis of `.pcap` files, with three verbosity levels from one-line-per-frame to fully expanded protocol fields.

Built for the "Network Services" course, M1 SIRIS.

## Highlights

- **Live capture** on any network interface (requires `sudo`)
- **Offline analysis** of `.pcap` files captured by `tcpdump` or Wireshark
- **Three verbosity levels** — concise, synthetic, fully expanded
- **BPF filtering** with named aliases for common patterns

## Supported protocols

| Layer | Protocols |
|------|-----------|
| **L2 — Link** | Ethernet, ARP, RARP |
| **L3 — Network** | IPv4 (incl. options, fragmentation), IPv6 (incl. extension headers) |
| **L4 — Transport** | TCP (with options), UDP, ICMP, ICMPv6, NDP |
| **L7 — Application** | DNS, DHCP / BOOTP, HTTP, FTP, SMTP, IMAP, POP3, Telnet |

## Prerequisites

```bash
sudo apt install libpcap-dev    # Debian / Ubuntu
sudo dnf install libpcap-devel  # RHEL / Fedora
```

## Build

```bash
make           # build the analyser binary
make clean
```

## Usage

```bash
./analyseur (-i <interface> | -o <file.pcap>) -v <level> [-f <filter>]
```

Live capture requires `sudo`.

### Options

| Flag | Description |
|------|-------------|
| `-i <interface>` | Capture live on interface (e.g. `eth0`, `wlo1`) |
| `-o <file>` | Analyze a saved `.pcap` file |
| `-v <1\|2\|3>` | Verbosity level |
| `-f <filter>` | BPF filter expression or named alias |
| `-h` | Help |

### Verbosity levels

- **`-v 1`** — one line per frame (timestamp, top-level protocol, length)
- **`-v 2`** — one line per protocol layer
- **`-v 3`** — every field, indented as a tree

## Examples

```bash
sudo ./analyseur -i wlo1 -v 2                 # live, layer-by-layer
./analyseur -o capture.pcap -v 3              # full dump from a saved capture
sudo ./analyseur -i eth0 -v 1 -f "port 53"    # DNS traffic only
```

## Project layout

```
.
├── src/            # Sources by protocol layer
├── include/        # Public headers
├── protocoles/     # Protocol parsers
├── makefile
└── README.md
```

## Author

**Loïc Waltzing** : individual project, M1 SIRIS.

## License

See [`LICENSE`](LICENSE). MIT.
