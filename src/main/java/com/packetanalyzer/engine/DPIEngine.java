package com.packetanalyzer.engine;

import com.packetanalyzer.model.Connection;
import com.packetanalyzer.model.DPIStats;
import com.packetanalyzer.model.FiveTuple;
import com.packetanalyzer.model.PacketInfo;
import com.packetanalyzer.parser.PcapReader;
import com.packetanalyzer.parser.PcapWriter;
import com.packetanalyzer.report.ReportGenerator;
import com.packetanalyzer.report.StatsCollector;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.IOException;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Collection;
import java.util.List;
import java.util.Map;
import java.util.concurrent.BlockingQueue;
import java.util.concurrent.LinkedBlockingQueue;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicLong;

/**
 * Main DPI Engine using the multi-threaded Load Balancer / Fast Path architecture.
 *
 * Matches the C++ dpi_mt.cpp architecture exactly:
 *
 *                     ┌─────────────────┐
 *                     │  Reader Thread   │
 *                     │  (reads PCAP)    │
 *                     └────────┬────────┘
 *                              │
 *               ┌──────────────┴──────────────┐
 *               │      hash(5-tuple) % N      │
 *               ▼                             ▼
 *     ┌─────────────────┐           ┌─────────────────┐
 *     │  LB0 Thread      │           │  LB1 Thread      │
 *     │  (Load Balancer) │           │  (Load Balancer) │
 *     └────────┬────────┘           └────────┬────────┘
 *              │                             │
 *       ┌──────┴──────┐               ┌──────┴──────┐
 *       │ hash % M    │               │ hash % M    │
 *       ▼             ▼               ▼             ▼
 * ┌──────────┐ ┌──────────┐   ┌──────────┐ ┌──────────┐
 * │FP0 Thread│ │FP1 Thread│   │FP2 Thread│ │FP3 Thread│
 * │(FastPath)│ │(FastPath)│   │(FastPath)│ │(FastPath)│
 * └─────┬────┘ └─────┬────┘   └─────┬────┘ └─────┬────┘
 *       │            │              │            │
 *       └────────────┴──────────────┴────────────┘
 *                           │
 *                           ▼
 *               ┌───────────────────────┐
 *               │   Output Queue        │
 *               └───────────┬───────────┘
 *                           │
 *                           ▼
 *               ┌───────────────────────┐
 *               │  Output Writer Thread │
 *               │  (writes to PCAP)     │
 *               └───────────────────────┘
 *
 * Why this design:
 *   - Load Balancers distribute work across Fast Paths
 *   - Fast Paths do the actual DPI processing
 *   - Consistent hashing: same 5-tuple always goes to the same FP
 *   - Each FP has its own flow table (no lock contention)
 *   - Output writer collects forwarded packets from all FPs
 */
public class DPIEngine {
    private static final Logger logger = LoggerFactory.getLogger(DPIEngine.class);

    private static final int DEFAULT_NUM_LBS = 2;
    private static final int DEFAULT_FPS_PER_LB = 2;
    private static final int QUEUE_CAPACITY = 10000;

    private final PcapReader pcapReader;
    private final PacketProcessor packetProcessor;
    private final RuleManager ruleManager;
    private final StatsCollector statsCollector;
    private final ReportGenerator reportGenerator;

    // Thread architecture
    private final List<LoadBalancer> loadBalancers = new ArrayList<>();
    private final List<FastPath> fastPaths = new ArrayList<>();
    private final List<Thread> lbThreads = new ArrayList<>();
    private final List<Thread> fpThreads = new ArrayList<>();

    // Output queue & writer
    private final BlockingQueue<PacketInfo> outputQueue = new LinkedBlockingQueue<>(QUEUE_CAPACITY);
    private PcapWriter pcapWriter;
    private String outputPath;
    private Thread outputWriterThread;

    // Control
    private final AtomicBoolean running = new AtomicBoolean(true);
    private final AtomicLong readerPacketCount = new AtomicLong(0);

    // Configuration
    private int numLBs = DEFAULT_NUM_LBS;
    private int fpsPerLB = DEFAULT_FPS_PER_LB;

    public DPIEngine() {
        this.pcapReader = new PcapReader();
        this.packetProcessor = new PacketProcessor();
        this.ruleManager = new RuleManager();
        this.statsCollector = new StatsCollector();
        this.reportGenerator = new ReportGenerator();

        // Load default rules
        ruleManager.loadDefaultRules();
    }

    /**
     * Configures the number of Load Balancer and Fast Path threads.
     * Matches C++ --lbs and --fps options.
     */
    public void setThreadConfig(int numLBs, int fpsPerLB) {
        this.numLBs = numLBs;
        this.fpsPerLB = fpsPerLB;
    }

    /**
     * Sets the output PCAP file path for forwarded packets.
     */
    public void setOutputPath(String outputPath) {
        this.outputPath = outputPath;
    }

    /**
     * Processes a PCAP file through the full multi-threaded DPI pipeline.
     */
    public void processFile(String filePath) {
        int totalFPs = numLBs * fpsPerLB;

        System.out.println();
        System.out.println("╔══════════════════════════════════════════════════════════════╗");
        System.out.println("║              DPI ENGINE v2.0 (Multi-threaded)                ║");
        System.out.printf("╠══════════════════════════════════════════════════════════════╣%n");
        System.out.printf("║ Load Balancers: %2d    FPs per LB: %2d    Total FPs: %2d        ║%n",
                numLBs, fpsPerLB, totalFPs);
        System.out.println("╚══════════════════════════════════════════════════════════════╝");
        System.out.println();

        logger.info("Processing file: {}", filePath);
        if (outputPath != null) {
            logger.info("Output file: {}", outputPath);
        }

        long startTime = System.currentTimeMillis();

        // Open output PCAP writer if configured
        if (outputPath != null) {
            try {
                pcapWriter = new PcapWriter();
                pcapWriter.open(outputPath);
            } catch (IOException e) {
                logger.error("Failed to open output file '{}': {}", outputPath, e.getMessage());
                return;
            }
        }

        // ---- Build the thread pipeline ----

        // Step 1: Create Fast Path threads (FPs)
        for (int i = 0; i < totalFPs; i++) {
            BlockingQueue<PacketInfo> fpQueue = new LinkedBlockingQueue<>(QUEUE_CAPACITY);
            FastPath fp = new FastPath(i, fpQueue, outputQueue, packetProcessor, ruleManager, running);
            fastPaths.add(fp);
        }

        // Step 2: Create Load Balancer threads (LBs)
        // Each LB is assigned a slice of the FPs
        for (int i = 0; i < numLBs; i++) {
            BlockingQueue<PacketInfo> lbQueue = new LinkedBlockingQueue<>(QUEUE_CAPACITY);
            // Assign FPs to this LB: LB_i gets FPs [i*fpsPerLB .. (i+1)*fpsPerLB)
            int fpStart = i * fpsPerLB;
            int fpEnd = fpStart + fpsPerLB;
            List<FastPath> assignedFPs = fastPaths.subList(fpStart, fpEnd);
            LoadBalancer lb = new LoadBalancer(i, lbQueue, assignedFPs, running);
            loadBalancers.add(lb);
        }

        // Step 3: Start FP threads
        for (FastPath fp : fastPaths) {
            Thread t = new Thread(fp, "FP-" + fp.getId());
            t.setDaemon(true);
            fpThreads.add(t);
            t.start();
        }

        // Step 4: Start LB threads
        for (LoadBalancer lb : loadBalancers) {
            Thread t = new Thread(lb, "LB-" + lb.getId());
            t.setDaemon(true);
            lbThreads.add(t);
            t.start();
        }

        // Step 5: Start Output Writer thread
        outputWriterThread = new Thread(this::outputWriterLoop, "OutputWriter");
        outputWriterThread.setDaemon(true);
        outputWriterThread.start();

        // ---- Reader Thread (this thread) ----
        // Reads PCAP and distributes packets to LBs via consistent hashing
        logger.info("[Reader] Processing packets...");

        try {
            pcapReader.read(filePath, packet -> {
                try {
                    // Pre-parse enough to get the five-tuple for hashing
                    // The FP will do full parsing, but we need basic IP info for LB routing
                    preParseForRouting(packet);

                    // Hash to select Load Balancer
                    int lbIndex = selectLoadBalancer(packet);
                    loadBalancers.get(lbIndex).getInputQueue().put(packet);
                    readerPacketCount.incrementAndGet();

                } catch (InterruptedException e) {
                    Thread.currentThread().interrupt();
                }
            });
        } catch (Exception e) {
            logger.error("Error reading PCAP: {}", e.getMessage());
        }

        logger.info("[Reader] Done reading {} packets", readerPacketCount.get());

        // ---- Shutdown pipeline ----
        // Signal all threads to stop after draining their queues
        running.set(false);

        // Wait for LB threads to finish
        for (Thread t : lbThreads) {
            try { t.join(30000); } catch (InterruptedException ignored) {}
        }

        // Wait for FP threads to finish
        for (Thread t : fpThreads) {
            try { t.join(30000); } catch (InterruptedException ignored) {}
        }

        // Wait for output writer to finish
        try { outputWriterThread.join(30000); } catch (InterruptedException ignored) {}

        // Close PCAP writer
        if (pcapWriter != null) {
            try { pcapWriter.close(); } catch (IOException e) {
                logger.error("Error closing output: {}", e.getMessage());
            }
        }

        long elapsed = System.currentTimeMillis() - startTime;
        logger.info("Processing completed in {} ms", elapsed);

        // ---- Collect stats from all FPs and generate report ----
        collectStatsFromFPs();
        DPIStats stats = statsCollector.getStats();
        reportGenerator.generateConsoleReport(stats, this);
    }

    /**
     * Pre-parses raw packet data to extract IP addresses and ports
     * for the Reader thread's LB routing hash.
     * Only does minimal parsing — full parsing happens in the FP.
     */
    private void preParseForRouting(PacketInfo packet) {
        byte[] raw = packet.getRawData();
        if (raw == null || raw.length < 34) return;

        // Quick Ethernet EtherType check
        int etherType = ((raw[12] & 0xFF) << 8) | (raw[13] & 0xFF);
        if (etherType != 0x0800) return; // Not IPv4

        // Quick IP header parse for src/dst IP and protocol
        int ipOffset = 14;
        int protocol = raw[ipOffset + 9] & 0xFF;
        packet.setProtocol(protocol);

        String srcIp = String.format("%d.%d.%d.%d",
                raw[ipOffset + 12] & 0xFF, raw[ipOffset + 13] & 0xFF,
                raw[ipOffset + 14] & 0xFF, raw[ipOffset + 15] & 0xFF);
        String dstIp = String.format("%d.%d.%d.%d",
                raw[ipOffset + 16] & 0xFF, raw[ipOffset + 17] & 0xFF,
                raw[ipOffset + 18] & 0xFF, raw[ipOffset + 19] & 0xFF);
        packet.setSrcIp(srcIp);
        packet.setDstIp(dstIp);

        // Quick port extraction for TCP/UDP
        int ihl = (raw[ipOffset] & 0x0F) * 4;
        int transportOffset = ipOffset + ihl;
        if (transportOffset + 4 <= raw.length && (protocol == 6 || protocol == 17)) {
            int srcPort = ((raw[transportOffset] & 0xFF) << 8) | (raw[transportOffset + 1] & 0xFF);
            int dstPort = ((raw[transportOffset + 2] & 0xFF) << 8) | (raw[transportOffset + 3] & 0xFF);
            packet.setSrcPort(srcPort);
            packet.setDstPort(dstPort);
        }
    }

    /**
     * Selects a Load Balancer using consistent hashing on the five-tuple.
     * Matches C++: hash(pkt.tuple) % num_lbs
     */
    private int selectLoadBalancer(PacketInfo packet) {
        int hash = 17;
        if (packet.getSrcIp() != null) hash = hash * 31 + packet.getSrcIp().hashCode();
        if (packet.getDstIp() != null) hash = hash * 31 + packet.getDstIp().hashCode();
        hash = hash * 31 + packet.getSrcPort();
        hash = hash * 31 + packet.getDstPort();
        hash = hash * 31 + packet.getProtocol();
        return Math.abs(hash) % numLBs;
    }

    /**
     * Output Writer Thread.
     * Pops forwarded packets from the output queue and writes them to the PCAP file.
     * Matches the C++ outputThread() function.
     */
    private void outputWriterLoop() {
        logger.info("[OutputWriter] Output writer thread started");
        long written = 0;

        while (running.get() || !outputQueue.isEmpty()) {
            try {
                PacketInfo packet = outputQueue.poll(100, TimeUnit.MILLISECONDS);
                if (packet == null) continue;

                if (pcapWriter != null && packet.getRawData() != null) {
                    Instant ts = packet.getTimestamp() != null ? packet.getTimestamp() : Instant.now();
                    pcapWriter.writePacket(packet.getRawData(), ts);
                    written++;
                }
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
                break;
            } catch (IOException e) {
                logger.error("[OutputWriter] Error writing packet: {}", e.getMessage());
            }
        }

        logger.info("[OutputWriter] Output writer thread stopped ({} packets written)", written);
    }

    /**
     * Collects statistics from all Fast Path threads into the central StatsCollector.
     */
    private void collectStatsFromFPs() {
        for (FastPath fp : fastPaths) {
            for (Connection conn : fp.getFlows().values()) {
                // The FP already counted processed/dropped/forwarded
                // We need to record each flow's packets in the central stats
            }
        }

        // Walk all FP flow tables to aggregate stats
        for (FastPath fp : fastPaths) {
            for (Map.Entry<FiveTuple, Connection> entry : fp.getFlows().entrySet()) {
                Connection conn = entry.getValue();
                // Create a summary PacketInfo for stats
                PacketInfo summary = new PacketInfo();
                summary.setProtocol(entry.getKey().getProtocol());
                summary.setSrcIp(entry.getKey().getSrcIp());
                summary.setDstIp(entry.getKey().getDstIp());
                summary.setSrcPort(entry.getKey().getSrcPort());
                summary.setDstPort(entry.getKey().getDstPort());
                summary.setAppType(conn.getAppType());
                summary.setDetectedDomain(conn.getDetectedDomain());
                summary.setLength((int) conn.getTotalBytes());

                // Record per-packet stats from flow
                for (int i = 0; i < conn.getPacketCount(); i++) {
                    statsCollector.recordPacket(summary);
                }
            }
        }
    }

    // ---- Accessors ----
    public RuleManager getRuleManager() { return ruleManager; }
    public List<LoadBalancer> getLoadBalancers() { return loadBalancers; }
    public List<FastPath> getFastPaths() { return fastPaths; }
    public long getReaderPacketCount() { return readerPacketCount.get(); }
    public StatsCollector getStatsCollector() { return statsCollector; }
}
