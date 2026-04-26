# 🔍 Packet Analyzer — Java DPI Engine

A high-performance, Java-based **Packet Analyzer** that reads PCAP capture files, parses multi-layer network protocols, performs **Deep Packet Inspection (DPI)**, extracts TLS Server Name Indication (SNI), tracks network flows, classifies applications, applies filtering rules, and generates comprehensive traffic reports.

---

## 📋 Table of Contents

- [Features](#-features)
- [Architecture](#-architecture)
- [Project Structure](#-project-structure)
- [Prerequisites](#-prerequisites)
- [Installation](#-installation)
- [Usage](#-usage)
- [Packet Processing Pipeline](#-packet-processing-pipeline)
- [Module Details](#-module-details)
  - [Model Layer](#model-layer)
  - [Parser Layer](#parser-layer)
  - [Engine Layer](#engine-layer)
  - [Utility Layer](#utility-layer)
  - [Report Layer](#report-layer)
- [Five-Tuple Flow Tracking](#-five-tuple-flow-tracking)
- [Deep Packet Inspection](#-deep-packet-inspection)
- [Rule-Based Filtering](#-rule-based-filtering)
- [Sample Output](#-sample-output)
- [Dependencies](#-dependencies)
- [Future Enhancements](#-future-enhancements)
- [License](#-license)

---

## ✨ Features

| Feature | Description |
|---|---|
| **PCAP Parsing** | Read and parse standard PCAP capture files using pcap4j |
| **Multi-Layer Protocol Parsing** | Parse Ethernet II, IPv4, TCP, and UDP headers from raw bytes |
| **Deep Packet Inspection** | Inspect packet payloads beyond header-level information |
| **TLS SNI Extraction** | Extract Server Name Indication from TLS ClientHello handshakes |
| **HTTP Host Extraction** | Extract domain from HTTP/1.x `Host:` header for plain HTTP traffic |
| **Application Classification** | Detect applications (YouTube, Google, GitHub, Netflix, etc.) via domain signatures and port heuristics |
| **Five-Tuple Flow Tracking** | Group packets into bidirectional flows using normalized five-tuples |
| **TCP Connection Tracking** | Track TCP connection state machines (NEW → ESTABLISHED → CLOSING → CLOSED → RESET) |
| **Rule-Based Filtering** | Block traffic by IP, domain, port, application type, or custom predicates |
| **Flow-Level Blocking** | Once a flow is identified as blocked, all subsequent packets in that flow are automatically dropped |
| **Filtered PCAP Output** | Write non-blocked (forwarded) packets to an output PCAP file |
| **CLI Arguments** | Command-line flags for `--block-app`, `--block-ip`, `--block-domain`, `--block-port` |
| **Statistics & Reporting** | Generate detailed traffic analysis reports with protocol distributions, domain lists, and connection summaries |
| **Multi-threaded Processing** | LB/FP thread architecture with consistent hashing, per-FP flow tables, and output writer thread |

---

## 🏗 Architecture

```
                    ┌─────────────────┐
                    │  Reader Thread   │
                    │  (reads PCAP)    │
                    └────────┬────────┘
                             │
              ┌──────────────┴──────────────┐
              │      hash(5-tuple) % N      │
              ▼                             ▼
    ┌─────────────────┐           ┌─────────────────┐
    │  LB0 Thread      │           │  LB1 Thread      │
    │  (Load Balancer) │           │  (Load Balancer) │
    └────────┬────────┘           └────────┬────────┘
             │                             │
      ┌──────┴──────┐               ┌──────┴──────┐
      │ hash % M    │               │ hash % M    │
      ▼             ▼               ▼             ▼
┌──────────┐ ┌──────────┐   ┌──────────┐ ┌──────────┐
│FP0 Thread│ │FP1 Thread│   │FP2 Thread│ │FP3 Thread│
│(FastPath)│ │(FastPath)│   │(FastPath)│ │(FastPath)│
└─────┬────┘ └─────┬────┘   └─────┬────┘ └─────┬────┘
      │            │              │            │
      └────────────┴──────────────┴────────────┘
                          │
                          ▼
              ┌───────────────────────┐
              │   Output Queue        │
              └───────────┬───────────┘
                          │
                          ▼
              ┌───────────────────────┐
              │  Output Writer Thread │
              │  (writes to PCAP)     │
              └───────────────────────┘
```

**Why this design:**
- **Load Balancers (LBs):** Distribute work across Fast Paths
- **Fast Paths (FPs):** Do the actual DPI processing with per-FP flow tables
- **Consistent Hashing:** Same 5-tuple always goes to the same FP (no lock contention)
- **Output Writer:** Collects forwarded packets from all FPs and writes to output PCAP

---

## 📁 Project Structure

```
packet_analyzer/
│
├── src/main/java/com/packetanalyzer/
│   ├── Main.java                          # Application entry point
│   │
│   ├── engine/                            # Core processing engine
│   │   ├── DPIEngine.java                 # Main pipeline orchestrator (LB/FP architecture)
│   │   ├── LoadBalancer.java              # Load Balancer thread (distributes to FPs)
│   │   ├── FastPath.java                  # Fast Path thread (DPI processing + per-FP flow table)
│   │   ├── PacketProcessor.java           # Protocol parsing pipeline
│   │   ├── RuleManager.java              # Filtering & blocking rules
│   │   ├── ConnectionTracker.java         # TCP connection state tracking
│   │   └── FlowManager.java              # Five-tuple flow management
│   │
│   ├── model/                             # Data models
│   │   ├── PacketInfo.java                # Packet data container
│   │   ├── FiveTuple.java                 # Flow identifier (5-tuple)
│   │   ├── Connection.java                # Connection aggregate
│   │   ├── AppType.java                   # Application type enum
│   │   └── DPIStats.java                  # Statistics accumulator
│   │
│   ├── parser/                            # Protocol parsers
│   │   ├── PcapReader.java                # PCAP file reader (pcap4j)
│   │   ├── PcapWriter.java                # PCAP output file writer
│   │   ├── EthernetParser.java            # Ethernet II frame parser
│   │   ├── IPParser.java                  # IPv4 header parser
│   │   ├── TCPParser.java                 # TCP segment parser
│   │   ├── UDPParser.java                 # UDP datagram parser
│   │   ├── TLSParser.java                # TLS ClientHello SNI extractor
│   │   └── HTTPParser.java               # HTTP Host header extractor
│   │
│   ├── utils/                             # Utility classes
│   │   ├── ByteUtils.java                 # Byte manipulation helpers
│   │   ├── IPUtils.java                   # IP address utilities
│   │   └── PacketUtils.java               # Packet-level utilities
│   │
│   └── report/                            # Reporting
│       ├── ReportGenerator.java           # Formatted report output
│       └── StatsCollector.java            # Statistics collection
│
├── input/                                 # Place PCAP files here
│   └── sample.pcap
│
├── output/                                # Filtered output files
│   └── filtered_output.pcap
│
├── pom.xml                                # Maven build configuration
├── CLAUDE.md                              # Project specification
├── README.md                              # This file
└── .gitignore                             # Git ignore rules
```

---

## 📦 Prerequisites

- **Java JDK 17+** (tested with OpenJDK 21)
- **Apache Maven 3.6+**
- **libpcap** (required by pcap4j for PCAP file reading)

### Installing libpcap

```bash
# Ubuntu / Debian
sudo apt-get install libpcap-dev

# CentOS / RHEL
sudo yum install libpcap-devel

# macOS
brew install libpcap
```

---

## 🚀 Installation

### 1. Clone the Repository

```bash
git clone https://github.com/your-username/packet-analyzer.git
cd packet-analyzer
```

### 2. Build the Project

```bash
mvn clean install
```

### 3. Verify the Build

```bash
mvn compile
```

You should see:
```
[INFO] Compiling 22 source files to .../target/classes
[INFO] BUILD SUCCESS
```

---

## 💻 Usage

### Basic Usage

Place a PCAP file in the `input/` directory and run:

```bash
mvn exec:java -Dexec.mainClass="com.packetanalyzer.Main"
```

This reads from the default path `input/sample.pcap`.

### Custom PCAP File

```bash
mvn exec:java -Dexec.mainClass="com.packetanalyzer.Main" -Dexec.args="/path/to/capture.pcap"
```

### With Filtering (Output PCAP + Blocking Rules)

Matches the C++ CLI interface:

```bash
# Process and write non-blocked packets to output
java -jar target/packet-analyzer-1.0-SNAPSHOT.jar input/sample.pcap output/filtered.pcap

# Block YouTube and Facebook traffic
java -jar target/packet-analyzer-1.0-SNAPSHOT.jar input/sample.pcap output/filtered.pcap \
    --block-app YouTube \
    --block-app Facebook

# Block by IP, domain, and port
java -jar target/packet-analyzer-1.0-SNAPSHOT.jar input/sample.pcap output/filtered.pcap \
    --block-ip 192.168.1.50 \
    --block-domain tiktok \
    --block-port 8080
```

### CLI Options

| Flag | Description | Example |
|---|---|---|
| `--block-app <name>` | Block by application type | `--block-app YouTube` |
| `--block-ip <ip>` | Block by IP address | `--block-ip 192.168.1.50` |
| `--block-domain <name>` | Block by domain (substring) | `--block-domain facebook` |
| `--block-port <port>` | Block by port number | `--block-port 8080` |
| `--help`, `-h` | Show help message | `--help` |

### Building a JAR

```bash
mvn clean package
java -jar target/packet-analyzer-1.0-SNAPSHOT.jar input/sample.pcap
```

### Generating a PCAP for Testing

If you don't have a PCAP file, you can capture one with `tcpdump`:

```bash
# Capture 100 packets on the default interface
sudo tcpdump -c 100 -w input/sample.pcap

# Capture only TCP traffic on port 443 (HTTPS/TLS)
sudo tcpdump -c 200 -w input/sample.pcap tcp port 443
```

---

## 🔄 Packet Processing Pipeline

Each packet flows through these stages sequentially:

```
  ┌──────────────┐
  │  PCAP File   │
  └──────┬───────┘
         ▼
  ┌──────────────┐
  │ PcapReader   │  Read raw bytes + timestamp via pcap4j
  └──────┬───────┘
         ▼
  ┌──────────────┐
  │  Ethernet    │  Parse Dst/Src MAC, EtherType, VLAN tags
  │  Parser      │
  └──────┬───────┘
         ▼
  ┌──────────────┐
  │  IP Parser   │  Parse IPv4: Src/Dst IP, Protocol, TTL, IHL
  └──────┬───────┘
         ▼
  ┌──────────────┐
  │ TCP / UDP    │  Parse ports, flags (SYN/ACK/FIN/RST),
  │ Parser       │  sequence numbers, payload extraction
  └──────┬───────┘
         ▼
  ┌──────────────┐
  │ TLS Parser   │  Extract SNI from ClientHello (port 443)
  └──────┬───────┘
         ▼
  ┌──────────────┐
  │ App Classify │  Domain-based → Port-based fallback
  └──────┬───────┘
         ▼
  ┌──────────────┐
  │ Flow Tracker │  Group into bidirectional flows (5-tuple)
  └──────┬───────┘
         ▼
  ┌──────────────┐
  │ Connection   │  Track TCP state (SYN→EST→FIN→CLOSED)
  │ Tracker      │
  └──────┬───────┘
         ▼
  ┌──────────────┐
  │ Rule Manager │  Evaluate IP/domain/port block rules
  └──────┬───────┘
         ▼
  ┌──────────────┐
  │ Stats &      │  Accumulate metrics, print report
  │ Report       │
  └──────────────┘
```

---

## 📦 Module Details

### Model Layer

| Class | Description |
|---|---|
| **`PacketInfo`** | Central data container populated layer-by-layer as the packet passes through each parser. Holds Ethernet, IP, TCP/UDP fields, payload, DPI results, flow association, and blocking state. |
| **`FiveTuple`** | Immutable flow identifier: `(srcIp, dstIp, srcPort, dstPort, protocol)`. Supports `normalized()` to ensure both directions of a connection map to the same key. |
| **`Connection`** | Aggregates all packets in a flow. Tracks state (NEW/ESTABLISHED/CLOSING/CLOSED/RESET), forward/backward byte counts, detected domains, and application type. |
| **`AppType`** | Enum of 20 application categories (HTTP, HTTPS, DNS, TLS, SSH, YouTube, Google, GitHub, Netflix, etc.) with human-readable names and descriptions. |
| **`DPIStats`** | Thread-safe statistics accumulator using `AtomicInteger`/`AtomicLong`. Tracks packet counts, protocol distribution, application classification, and domain frequencies. |

### Parser Layer

| Class | Description |
|---|---|
| **`PcapReader`** | Reads PCAP files via pcap4j. Supports both batch mode (`readAll()`) and streaming mode (`read(path, consumer)`) for memory efficiency. |
| **`PcapWriter`** | Writes filtered (forwarded) packets to an output PCAP file with proper global and per-packet headers. Thread-safe via `synchronized`. |
| **`EthernetParser`** | Parses 14-byte Ethernet II frames: destination MAC, source MAC, EtherType. Handles 802.1Q VLAN tagging transparently. |
| **`IPParser`** | Parses 20-60 byte IPv4 headers: version, IHL, total length, TTL, protocol number, source/destination IP addresses. |
| **`TCPParser`** | Parses 20-60 byte TCP headers: ports, sequence/ack numbers, data offset, flags (SYN/ACK/FIN/RST/PSH), window size. Extracts payload bytes. |
| **`UDPParser`** | Parses 8-byte UDP headers: ports, length. Extracts payload with truncated-packet handling. |
| **`TLSParser`** | Identifies TLS handshake records (content type `0x16`), extracts TLS version, and walks through ClientHello extensions to find the SNI hostname (extension type `0x0000`). |
| **`HTTPParser`** | Parses HTTP/1.x request headers to extract the `Host:` header value for plain HTTP domain detection (port 80). Matches C++ `HTTPHostExtractor`. |

### Engine Layer

| Class | Description |
|---|---|
| **`DPIEngine`** | Top-level orchestrator matching C++ `dpi_mt.cpp`. Drives: read → parse → classify → track → block → forward/drop → report. Supports PCAP output and flow-level blocking. |
| **`PacketProcessor`** | Runs a single packet through Ethernet → IP → TCP/UDP → TLS/HTTP → Application classification. Matches C++ `packet_parser.cpp` + `sni_extractor.cpp`. |
| **`FlowManager`** | Groups packets into bidirectional flows using normalized five-tuples. Uses `ConcurrentHashMap` for thread safety. |
| **`ConnectionTracker`** | Maintains per-flow TCP state machines. Tracks active vs. total connections. |
| **`RuleManager`** | Evaluates blocking rules: IP blocklist, **app blocklist**, domain blocklist (substring match), port blocklist, and custom `Predicate<PacketInfo>` rules. Matches C++ `rule_manager.h`. |

### Utility Layer

| Class | Description |
|---|---|
| **`ByteUtils`** | Low-level byte manipulation: `readUint8/16/32` (big-endian), `extractBytes`, `toHexString`, `toMacAddress`, `toAsciiString`, bounds checking. |
| **`IPUtils`** | IP address utilities: byte↔string conversion, validation, private/broadcast/multicast detection, protocol number→name mapping. |
| **`PacketUtils`** | Port-based application classification, port range checks (well-known/registered/ephemeral), byte formatting, EtherType naming, TCP flag formatting. |

### Report Layer

| Class | Description |
|---|---|
| **`StatsCollector`** | Thin wrapper that delegates packet recording to `DPIStats`. |
| **`ReportGenerator`** | Generates formatted console reports with sections: Packet Summary, Filtering Summary, Application Classification, Detected Domains, Flow Summary, Connection Summary, and Top Connections. |

---

## 🔗 Five-Tuple Flow Tracking

Each network connection is uniquely identified by a **five-tuple**:

| Field | Description | Example |
|---|---|---|
| Source IP | Sender's IP address | `192.168.1.100` |
| Destination IP | Receiver's IP address | `142.250.190.46` |
| Source Port | Sender's port number | `52481` |
| Destination Port | Receiver's port number | `443` |
| Protocol | Transport protocol number | `6` (TCP) |

### Bidirectional Normalization

The `FiveTuple.normalized()` method ensures both directions of a conversation map to the same flow key:

```
Client → Server:  192.168.1.100:52481 → 142.250.190.46:443 [TCP]
Server → Client:  142.250.190.46:443 → 192.168.1.100:52481 [TCP]
                  ↓ normalized() ↓
Both map to:      142.250.190.46:443 → 192.168.1.100:52481 [TCP]
```

---

## 🔬 Deep Packet Inspection

### TLS SNI Extraction

The analyzer inspects TLS ClientHello messages to extract the **Server Name Indication (SNI)** — the hostname the client is connecting to. This works even though the traffic is encrypted.

**How it works:**
1. Detect TLS handshake record (content type `0x16`)
2. Identify ClientHello message (handshake type `0x01`)
3. Skip session ID, cipher suites, and compression methods
4. Walk through TLS extensions
5. Extract hostname from SNI extension (type `0x0000`)

### Application Classification

Traffic is classified using a two-tier approach:

**Tier 1 — Domain-based** (highest priority):
| Domain Pattern | Classification |
|---|---|
| `youtube.com`, `googlevideo.com` | YouTube |
| `google.com` | Google |
| `github.com` | GitHub |
| `facebook.com`, `fbcdn.net` | Facebook |
| `twitter.com`, `twimg.com` | Twitter |
| `netflix.com`, `nflx.net` | Netflix |
| `amazon.com`, `aws` | Amazon |
| `microsoft.com`, `azure`, `msn` | Microsoft |

**Tier 2 — Port-based** (fallback):
| Port | Classification |
|---|---|
| 80 | HTTP |
| 443 | HTTPS/TLS |
| 53 | DNS |
| 22 | SSH |
| 21/20 | FTP |
| 25/587 | SMTP |
| 123 | NTP |

---

## 🛡 Rule-Based Filtering

The `RuleManager` supports multiple types of blocking rules, matching the C++ `rule_manager.h`:

```java
DPIEngine engine = new DPIEngine();

// Block by application type (matches C++ --block-app)
engine.getRuleManager().blockApp("YouTube");
engine.getRuleManager().blockApp(AppType.FACEBOOK);

// Block by IP address (matches C++ --block-ip)
engine.getRuleManager().blockIp("192.168.1.50");

// Block by domain substring (matches C++ --block-domain)
engine.getRuleManager().blockDomain("tiktok");

// Block by port
engine.getRuleManager().blockPort(8080);

// Custom predicate rule
engine.getRuleManager().addCustomRule(packet ->
    packet.getPayloadLength() > 10000  // Block large payloads
);

// Set output file for forwarded (non-blocked) packets
engine.setOutputPath("output/filtered.pcap");

engine.processFile("input/sample.pcap");
```

### Flow-Level Blocking

Blocking operates at the **flow level**, matching the C++ behavior:

```
Connection to YouTube:
  Packet 1 (SYN)           → No SNI yet, FORWARD
  Packet 2 (SYN-ACK)       → No SNI yet, FORWARD
  Packet 3 (ACK)           → No SNI yet, FORWARD
  Packet 4 (Client Hello)  → SNI: www.youtube.com
                           → App: YOUTUBE (blocked!)
                           → Mark flow as BLOCKED
                           → DROP this packet
  Packet 5 (Data)          → Flow is BLOCKED → DROP
  Packet 6 (Data)          → Flow is BLOCKED → DROP
  ...all subsequent packets → DROP
```

Once a flow is identified and blocked, all subsequent packets of that flow are automatically dropped — even before re-evaluating individual rules.

---

## 📊 Sample Output

```
=======================================================
          PACKET ANALYZER - DPI REPORT
=======================================================

--- Packet Summary ---
  Total Packets:       150
  TCP Packets:         110
  UDP Packets:         40
  Other Packets:       0
  Malformed Packets:   0
  Total Bytes:         125.40 KB

--- Filtering Summary ---
  Forwarded Packets:   138
  Dropped Packets:     12
  Blocked Packets:     12
  TLS Packets:         45

--- Application Classification ---
  HTTPS               65 packets
  YouTube              20 packets
  Google               15 packets
  DNS                  25 packets
  GitHub               10 packets
  HTTP                  8 packets
  Unknown               7 packets

--- Detected Domains ---
  - youtube.com                        (12 packets)
  - www.google.com                     (10 packets)
  - github.com                         (8 packets)
  - fonts.googleapis.com               (5 packets)

--- Flow Summary ---
  Total Flows:         23

--- Connection Summary ---
  Total Connections:   18
  Active Connections:  5

--- Top Connections (by packet count) ---
  192.168.1.100:52481 -> 142.250.190.46:443 [TCP]
    Packets: 25 | Bytes: 15.20 KB | State: ESTABLISHED | Domain: youtube.com | App: YouTube
  192.168.1.100:48832 -> 140.82.121.4:443 [TCP]
    Packets: 18 | Bytes: 8.50 KB | State: ESTABLISHED | Domain: github.com | App: GitHub

=======================================================
          END OF REPORT
=======================================================
```

---

## 📚 Dependencies

| Dependency | Version | Purpose |
|---|---|---|
| [pcap4j-core](https://github.com/kaitoy/pcap4j) | 1.8.2 | PCAP file reading and packet capture |
| [pcap4j-packetfactory-static](https://github.com/kaitoy/pcap4j) | 1.8.2 | Static packet factory for pcap4j |
| [slf4j-simple](https://www.slf4j.org/) | 2.0.9 | Simple logging facade implementation |

All dependencies are managed via Maven and downloaded automatically during build.

---

## 🔮 Future Enhancements

- [ ] **Live Packet Sniffing** — Real-time capture from network interfaces
- [ ] **Real-Time Traffic Dashboard** — Web-based UI for live monitoring
- [ ] **Threat Detection** — Signature-based intrusion detection
- [ ] **HTTP/3 & QUIC Support** — Parse UDP-based QUIC protocol
- [ ] **Geo-IP Lookup** — Map IP addresses to geographic locations
- [ ] **Intrusion Detection System** — Pattern matching against known attack signatures
- [ ] **IPv6 Support** — Parse IPv6 headers and extension headers
- [ ] **JSON/CSV Report Export** — Machine-readable report formats
- [ ] **LB/FP Thread Architecture** — Load Balancer + Fast Path consistent-hashing threads (like C++ version)
- [ ] **Per-Thread Statistics** — Thread-level processing metrics in report output
- [x] **Multi-threaded Processing** — Parallel packet processing for large captures
- [x] **PCAP Output** — Write filtered (forwarded) packets to output PCAP files
- [x] **HTTP Host Extraction** — Domain detection for plain HTTP traffic
- [x] **App-Type Blocking** — Block traffic by application type (--block-app)
- [x] **Flow-Level Blocking** — Once a flow is blocked, all subsequent packets are dropped
- [x] **CLI Arguments** — Command-line flags for blocking rules

---

## 📄 License

This project is open source and available under the [MIT License](LICENSE).

---

> **Note:** This Java implementation is inspired by DPI Engine architecture principles for educational and research purposes.
