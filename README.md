# DPI Engine - Deep Packet Inspection System (Java Edition)

This document explains **everything** about this project - from basic networking concepts to the complete code architecture. After reading this, you should understand exactly how packets flow through the system without needing to read the code.

---

## Table of Contents

1. [What is DPI?](#1-what-is-dpi)
2. [Networking Background](#2-networking-background)
3. [Project Overview](#3-project-overview)
4. [File Structure](#4-file-structure)
5. [The Journey of a Packet](#5-the-journey-of-a-packet)
6. [Multi-threaded Architecture](#6-multi-threaded-architecture)
7. [Deep Dive: Each Component](#7-deep-dive-each-component)
8. [How SNI Extraction Works](#8-how-sni-extraction-works)
9. [How Blocking Works](#9-how-blocking-works)
10. [Building and Running](#10-building-and-running)
11. [Understanding the Output](#11-understanding-the-output)

---

## 1. What is DPI?

**Deep Packet Inspection (DPI)** is a technology used to examine the contents of network packets as they pass through a checkpoint. Unlike simple firewalls that only look at packet headers (source/destination IP), DPI looks *inside* the packet payload.

### Real-World Uses:
- **ISPs**: Throttle or block certain applications (e.g., BitTorrent)
- **Enterprises**: Block social media on office networks
- **Parental Controls**: Block inappropriate websites
- **Security**: Detect malware or intrusion attempts

### What Our DPI Engine Does:
```
User Traffic (PCAP) → [DPI Engine] → Filtered Traffic (PCAP)
                           ↓
                    - Identifies apps (YouTube, Facebook, etc.)
                    - Blocks based on rules
                    - Generates reports
```

---

## 2. Networking Background

### The Network Stack (Layers)

When you visit a website, data travels through multiple "layers":

```
┌─────────────────────────────────────────────────────────┐
│ Layer 7: Application    │ HTTP, TLS, DNS               │
├─────────────────────────────────────────────────────────┤
│ Layer 4: Transport      │ TCP (reliable), UDP (fast)   │
├─────────────────────────────────────────────────────────┤
│ Layer 3: Network        │ IP addresses (routing)       │
├─────────────────────────────────────────────────────────┤
│ Layer 2: Data Link      │ MAC addresses (local network)│
└─────────────────────────────────────────────────────────┘
```

### A Packet's Structure

Every network packet is like a **Russian nesting doll** - headers wrapped inside headers:

```
┌──────────────────────────────────────────────────────────────────┐
│ Ethernet Header (14 bytes)                                       │
│ ┌──────────────────────────────────────────────────────────────┐ │
│ │ IP Header (20+ bytes)                                        │ │
│ │ ┌──────────────────────────────────────────────────────────┐ │ │
│ │ │ TCP Header (20+ bytes)                                   │ │ │
│ │ │ ┌──────────────────────────────────────────────────────┐ │ │ │
│ │ │ │ Payload (Application Data)                           │ │ │ │
│ │ │ │ e.g., TLS Client Hello with SNI                      │ │ │ │
│ │ │ └──────────────────────────────────────────────────────┘ │ │ │
│ │ └──────────────────────────────────────────────────────────┘ │ │
│ └──────────────────────────────────────────────────────────────┘ │
└──────────────────────────────────────────────────────────────────┘
```

### The Five-Tuple

A **connection** (or "flow") is uniquely identified by 5 values:

| Field | Example | Purpose |
|-------|---------|---------|
| Source IP | 192.168.1.100 | Who is sending |
| Destination IP | 172.217.14.206 | Where it's going |
| Source Port | 54321 | Sender's application identifier |
| Destination Port | 443 | Service being accessed (443 = HTTPS) |
| Protocol | TCP (6) | TCP or UDP |

**Why is this important?** 
- All packets with the same 5-tuple belong to the same connection
- If we block one packet of a connection, we should block all of them
- This is how we "track" conversations between computers

### What is SNI?

**Server Name Indication (SNI)** is part of the TLS/HTTPS handshake. When you visit `https://www.youtube.com`:

1. Your browser sends a "Client Hello" message
2. This message includes the domain name in **plaintext** (not encrypted yet!)
3. The server uses this to know which certificate to send

```
TLS Client Hello:
├── Version: TLS 1.2
├── Random: [32 bytes]
├── Cipher Suites: [list]
└── Extensions:
    └── SNI Extension:
        └── Server Name: "www.youtube.com"  ← We extract THIS!
```

**This is the key to DPI**: Even though HTTPS is encrypted, the domain name is visible in the first packet!

---

## 3. Project Overview

### What This Project Does

```
┌─────────────┐     ┌─────────────┐     ┌─────────────┐
│ Wireshark   │     │ DPI Engine  │     │ Output      │
│ Capture     │ ──► │ (Java)      │ ──► │ PCAP        │
│ (input.pcap)│     │ - Parse     │     │ (filtered)  │
└─────────────┘     │ - Classify  │     └─────────────┘
                    │ - Block     │
                    │ - Report    │
                    └─────────────┘
```

The system is built entirely in **Java** and uses a multi-threaded architecture to ensure high-performance processing, modeled after high-speed network appliances.

---

## 4. File Structure

```
packet_analyzer/
├── src/main/java/com/packetanalyzer/
│   ├── Main.java                 # Entry point & CLI parsing
│   ├── engine/                   # Core Processing Architecture
│   │   ├── DPIEngine.java        # Main orchestrator
│   │   ├── LoadBalancer.java     # LB thread implementation
│   │   ├── FastPath.java         # Worker thread implementation
│   │   ├── PacketProcessor.java  # Coordination of parsing
│   │   ├── RuleManager.java      # Blocking rules
│   │   ├── FlowManager.java      # Flow tracking management
│   │   └── ConnectionTracker.java# Individual connection state
│   │
│   ├── model/                    # Data structures
│   │   ├── Connection.java       # Flow state data
│   │   ├── FiveTuple.java        # Unique flow identifier
│   │   ├── PacketInfo.java       # Packet metadata
│   │   ├── AppType.java          # Enums for detected apps
│   │   └── DPIStats.java         # Statistics record
│   │
│   ├── parser/                   # Protocol parsing
│   │   ├── PcapReader.java       # PCAP file reading
│   │   ├── PcapWriter.java       # PCAP file writing
│   │   ├── TLSParser.java        # SNI extraction
│   │   ├── HTTPParser.java       # Host header extraction
│   │   └── Ethernet/IP/TCP/UDPParser.java # Headers
│   │
│   ├── report/                   # Output Generation
│   └── utils/                    # Helper functions
│
├── pom.xml                       # Maven build configuration
└── README.md                     # This file!
```

---

## 5. The Journey of a Packet

Let's trace a single packet through the system:

### Step 1: Read PCAP File

```java
PcapReader reader = new PcapReader();
reader.read(filePath, packet -> {
    // Process raw packet
});
```

**What happens:**
1. Open the file in binary mode
2. Read the 24-byte global header
3. Read the 16-byte packet header and variable-length data

### Step 2: Pre-Parse and Route

```java
preParseForRouting(packet);
int lbIndex = selectLoadBalancer(packet);
loadBalancers.get(lbIndex).getInputQueue().put(packet);
```

**What happens:**
1. Quickly extract IP and Port to create a basic 5-tuple
2. Hash the 5-tuple to determine which Load Balancer (LB) thread gets the packet
3. Send to LB queue

### Step 3: Fast Path Processing

```java
// Inside FastPath.java
PacketInfo parsed = packetProcessor.parse(rawPacket);
Connection flow = flowManager.getOrCreateFlow(parsed.getFiveTuple());
```

**What happens:**
1. The packet reaches a `FastPath` thread
2. `PacketProcessor` calls `EthernetParser`, `IPParser`, `TCPParser`, etc.
3. Retrieves the active `Connection` (Flow) from a local HashMap.

### Step 4: Extract SNI / Deep Packet Inspection

```java
// Inside TLSParser.java
if (isTlsClientHello(payload)) {
    String sni = extractSNI(payload);
    if (sni != null) {
        flow.setDetectedDomain(sni);
        flow.setAppType(AppType.fromDomain(sni));
    }
}
```

### Step 5: Check Blocking Rules

```java
if (ruleManager.isBlocked(parsed)) {
    flow.setBlocked(true);
}
```

### Step 6: Forward or Drop

```java
if (flow.isBlocked()) {
    stats.incrementDropped();
} else {
    stats.incrementForwarded();
    outputQueue.put(parsed);
}
```

---

## 6. Multi-threaded Architecture

The `DPIEngine` uses a **parallel** design for high performance:

```
                    ┌─────────────────┐
                    │  Reader Thread  │
                    │  (reads PCAP)   │
                    └────────┬────────┘
                             │
              ┌──────────────┴──────────────┐
              │      hash(5-tuple) % N      │
              ▼                             ▼
    ┌─────────────────┐           ┌─────────────────┐
    │  LB0 Thread     │           │  LB1 Thread     │
    │  (Load Balancer)│           │  (Load Balancer)│
    └────────┬────────┘           └────────┬────────┘
             │                             │
      ┌──────┴──────┐               ┌──────┴──────┐
      │hash % M     │               │hash % M     │
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

### Why This Design?

1. **Load Balancers (LBs):** Distribute work across FPs
2. **Fast Paths (FPs):** Do the actual DPI processing
3. **Consistent Hashing:** Same 5-tuple always goes to same FP

**Why consistent hashing matters:**
```
Connection: 192.168.1.100:54321 → 142.250.185.206:443

Packet 1 (SYN):         hash → FP2
Packet 2 (SYN-ACK):     hash → FP2  (same FP!)
Packet 3 (Client Hello): hash → FP2  (same FP!)
Packet 4 (Data):        hash → FP2  (same FP!)

All packets of this connection go to FP2.
FP2 can track the flow state correctly without needing complex thread locks on the flow table.
```

The system heavily utilizes Java's `java.util.concurrent.BlockingQueue` (specifically `LinkedBlockingQueue`) for thread-safe communication between stages.

---

## 7. Deep Dive: Each Component

### PcapReader.java

**Purpose:** Read network captures saved by Wireshark in Java using `DataInputStream`.

**Important concepts:** PCAP data is typically little-endian. Java natively reads binary data as big-endian. The reader uses utilities like `Integer.reverseBytes()` to correctly parse PCAP headers.

### Protocol Parsers (TCPParser, IPParser, etc.)

**Purpose:** Extract protocol fields from `byte[]` arrays.

```java
// Network Byte Order (Big-Endian) is standard for protocols
// Extracting a 16-bit port in Java:
int port = ((raw[offset] & 0xFF) << 8) | (raw[offset + 1] & 0xFF);
```

### TLSParser.java / HTTPParser.java

**Purpose:** Extract domain names from application payloads.

**For TLS (HTTPS):**
- Verify TLS record header (0x16)
- Verify Client Hello handshake (0x01)
- Parse through Session ID, Cipher Suites
- Find SNI Extension (Type 0x0000)

**For HTTP:**
- Convert payload to String
- Search for `Host: ` header
- Extract value until carriage return `\r`

### Data Models (FiveTuple, Connection)

**FiveTuple:**
```java
public class FiveTuple {
    private String srcIp;
    private String dstIp;
    private int srcPort;
    private int dstPort;
    private int protocol;
    
    // override equals() and hashCode() for HashMap keys
}
```

---

## 8. How SNI Extraction Works

When you visit `https://www.youtube.com`:

```
┌──────────┐                              ┌──────────┐
│  Browser │                              │  Server  │
└────┬─────┘                              └────┬─────┘
     │                                         │
     │ ──── Client Hello ─────────────────────►│
     │      (includes SNI: www.youtube.com)    │
     │                                         │
     │ ◄─── Server Hello ───────────────────── │
     │      (includes certificate)             │
     │                                         │
     │ ──── Key Exchange ─────────────────────►│
     │                                         │
     │ ◄═══ Encrypted Data ══════════════════► │
     │      (from here on, everything is       │
     │       encrypted - we can't see it)      │
```

**We can only extract SNI from the Client Hello!**

### TLS Client Hello Structure

```
Byte 0:     Content Type = 0x16 (Handshake)
Bytes 1-2:  Version = 0x0301 (TLS 1.0)
Bytes 3-4:  Record Length

-- Handshake Layer --
Byte 5:     Handshake Type = 0x01 (Client Hello)
...
-- Extensions --
Bytes X-X+1: Extensions Length
For each extension:
    Bytes: Extension Type (2)
    Bytes: Extension Length (2)
    Bytes: Extension Data

-- SNI Extension (Type 0x0000) --
Extension Type: 0x0000
Extension Length: L
  SNI List Length: M
  SNI Type: 0x00 (hostname)
  SNI Length: K
  SNI Value: "www.youtube.com" ← THE GOAL!
```

Our `TLSParser` navigates this structure using byte offsets to safely extract the string without causing `IndexOutOfBoundsException`.

---

## 9. How Blocking Works

### Rule Types

| Rule Type | CLI Flag | Example | What it Blocks |
|-----------|----------|---------|----------------|
| IP | `--block-ip` | `192.168.1.50` | All traffic from/to this IP |
| App | `--block-app` | `YouTube` | All connections classified as YouTube |
| Domain | `--block-domain`| `tiktok` | Any SNI or Host containing "tiktok" |
| Port | `--block-port`| `8080` | Traffic on this specific port |

### Flow-Based Blocking

**Important:** We block at the *flow* level, not packet level.

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

**Why this approach?**
- We can't identify the app until we see the Client Hello
- Once identified, we block all future packets of that flow
- The connection will fail/timeout on the client

---

## 10. Building and Running

### Prerequisites

- **Java 11 or higher**
- **Maven** (optional, but typical for building)

### Build Command

```bash
mvn clean package
```
*This generates a runnable JAR, typically `target/packet-analyzer-1.0-SNAPSHOT.jar`.*

### Running

**Basic usage:**
```bash
java -jar target/packet-analyzer-1.0-SNAPSHOT.jar test_dpi.pcap output.pcap
```

**With blocking:**
```bash
java -jar target/packet-analyzer-1.0-SNAPSHOT.jar test_dpi.pcap output.pcap \
    --block-app YouTube \
    --block-app TikTok \
    --block-ip 192.168.1.50 \
    --block-domain facebook
```

**Configure threads:**
```bash
java -jar target/packet-analyzer-1.0-SNAPSHOT.jar input.pcap output.pcap --lbs 4 --fps 4
# Creates 4 LB threads × 4 FP threads = 16 processing threads
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

