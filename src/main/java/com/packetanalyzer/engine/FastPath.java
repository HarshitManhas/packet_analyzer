package com.packetanalyzer.engine;

import com.packetanalyzer.model.AppType;
import com.packetanalyzer.model.Connection;
import com.packetanalyzer.model.FiveTuple;
import com.packetanalyzer.model.PacketInfo;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.Map;
import java.util.concurrent.BlockingQueue;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.LinkedBlockingQueue;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicLong;

/**
 * Fast Path (FP) processing thread.
 * Each FP has its own flow table (no lock contention) and processes
 * packets assigned to it via consistent hashing.
 *
 * Matches the C++ FastPath thread from dpi_mt.cpp:
 *   - Pops packets from its input queue
 *   - Looks up flow in local flow table
 *   - Classifies traffic (SNI extraction)
 *   - Checks blocking rules
 *   - Forwards non-blocked packets to the output queue
 */
public class FastPath implements Runnable {
    private static final Logger logger = LoggerFactory.getLogger(FastPath.class);

    private final int id;
    private final BlockingQueue<PacketInfo> inputQueue;
    private final BlockingQueue<PacketInfo> outputQueue;
    private final PacketProcessor packetProcessor;
    private final RuleManager ruleManager;
    private final AtomicBoolean running;

    // Each FP has its own flow table — no contention with other FPs
    // This is safe because consistent hashing ensures the same 5-tuple
    // always routes to the same FP
    private final Map<FiveTuple, Connection> flows = new ConcurrentHashMap<>();

    // Per-thread statistics
    private final AtomicLong processedCount = new AtomicLong(0);
    private final AtomicLong droppedCount = new AtomicLong(0);
    private final AtomicLong forwardedCount = new AtomicLong(0);

    public FastPath(int id,
                    BlockingQueue<PacketInfo> inputQueue,
                    BlockingQueue<PacketInfo> outputQueue,
                    PacketProcessor packetProcessor,
                    RuleManager ruleManager,
                    AtomicBoolean running) {
        this.id = id;
        this.inputQueue = inputQueue;
        this.outputQueue = outputQueue;
        this.packetProcessor = packetProcessor;
        this.ruleManager = ruleManager;
        this.running = running;
    }

    @Override
    public void run() {
        logger.info("[FP{}] Fast Path thread started", id);

        while (running.get() || !inputQueue.isEmpty()) {
            try {
                PacketInfo packet = inputQueue.poll(100, java.util.concurrent.TimeUnit.MILLISECONDS);
                if (packet == null) continue;

                processPacket(packet);

            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
                break;
            }
        }

        logger.info("[FP{}] Fast Path thread stopped (processed: {}, dropped: {}, forwarded: {})",
                id, processedCount.get(), droppedCount.get(), forwardedCount.get());
    }

    /**
     * Processes a single packet through the DPI pipeline.
     * Matches the C++ FastPath::run() logic.
     */
    private void processPacket(PacketInfo packet) {
        processedCount.incrementAndGet();

        // Step 1: Parse protocol layers
        boolean parsed = packetProcessor.process(packet);
        if (!parsed) {
            return; // Malformed packet
        }

        // Step 2: Look up flow in local flow table
        // Each FP has its own table — same 5-tuple always comes here
        if (packet.getSrcIp() != null && packet.getDstIp() != null) {
            FiveTuple tuple = new FiveTuple(
                    packet.getSrcIp(), packet.getDstIp(),
                    packet.getSrcPort(), packet.getDstPort(),
                    packet.getProtocol()
            );
            packet.setFiveTuple(tuple);

            FiveTuple normalized = tuple.normalized();
            Connection flow = flows.computeIfAbsent(normalized, Connection::new);
            flow.addPacket(packet);

            // Step 3: Flow-level blocking
            // If flow was previously blocked, auto-drop all subsequent packets
            if (isFlowBlocked(flow)) {
                packet.setBlocked(true);
                packet.setBlockReason("Flow previously blocked");
            }
        }

        // Step 4: Check blocking rules (IP, App, Domain, Port)
        if (!packet.isBlocked()) {
            ruleManager.evaluate(packet);
        }

        // Step 5: Forward or Drop
        if (packet.isBlocked()) {
            droppedCount.incrementAndGet();
        } else {
            forwardedCount.incrementAndGet();
            try {
                outputQueue.put(packet);
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
            }
        }
    }

    /**
     * Checks if a flow has been blocked (by app type or domain).
     * Once blocked, all future packets of this flow are dropped.
     */
    private boolean isFlowBlocked(Connection flow) {
        if (flow.getAppType() != null && ruleManager.getBlockedApps().contains(flow.getAppType())) {
            return true;
        }
        if (flow.getDetectedDomain() != null) {
            String domain = flow.getDetectedDomain().toLowerCase();
            for (String blocked : ruleManager.getBlockedDomains()) {
                if (domain.contains(blocked)) {
                    return true;
                }
            }
        }
        return false;
    }

    // ---- Accessors ----
    public int getId() { return id; }
    public BlockingQueue<PacketInfo> getInputQueue() { return inputQueue; }
    public long getProcessedCount() { return processedCount.get(); }
    public long getDroppedCount() { return droppedCount.get(); }
    public long getForwardedCount() { return forwardedCount.get(); }
    public Map<FiveTuple, Connection> getFlows() { return flows; }
}
