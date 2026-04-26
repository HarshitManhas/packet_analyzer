package com.packetanalyzer.engine;

import com.packetanalyzer.model.PacketInfo;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.List;
import java.util.concurrent.BlockingQueue;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicLong;

/**
 * Load Balancer (LB) thread.
 * Receives packets from the Reader thread and distributes them
 * to Fast Path threads using consistent hashing on the five-tuple.
 *
 * Matches the C++ LoadBalancer thread from dpi_mt.cpp:
 *   - Pops packets from its input queue
 *   - Hashes the 5-tuple to select a Fast Path
 *   - Pushes the packet to that FP's input queue
 *
 * Consistent hashing ensures all packets of the same connection
 * go to the same FP, so each FP can track flow state independently.
 */
public class LoadBalancer implements Runnable {
    private static final Logger logger = LoggerFactory.getLogger(LoadBalancer.class);

    private final int id;
    private final BlockingQueue<PacketInfo> inputQueue;
    private final List<FastPath> fastPaths;
    private final AtomicBoolean running;

    // Per-thread statistics
    private final AtomicLong dispatchedCount = new AtomicLong(0);

    public LoadBalancer(int id,
                        BlockingQueue<PacketInfo> inputQueue,
                        List<FastPath> fastPaths,
                        AtomicBoolean running) {
        this.id = id;
        this.inputQueue = inputQueue;
        this.fastPaths = fastPaths;
        this.running = running;
    }

    @Override
    public void run() {
        logger.info("[LB{}] Load Balancer thread started (distributing to {} FPs)",
                id, fastPaths.size());

        while (running.get() || !inputQueue.isEmpty()) {
            try {
                PacketInfo packet = inputQueue.poll(100, TimeUnit.MILLISECONDS);
                if (packet == null) continue;

                // Hash five-tuple to select Fast Path
                int fpIndex = selectFastPath(packet);
                FastPath fp = fastPaths.get(fpIndex);

                // Push to FP's input queue
                fp.getInputQueue().put(packet);
                dispatchedCount.incrementAndGet();

            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
                break;
            }
        }

        logger.info("[LB{}] Load Balancer thread stopped (dispatched: {})",
                id, dispatchedCount.get());
    }

    /**
     * Selects a Fast Path index using consistent hashing on the packet's five-tuple.
     * Same 5-tuple always maps to the same FP — this is critical for flow tracking.
     *
     * Matches the C++ hashing: hash(pkt.tuple) % num_fps
     */
    private int selectFastPath(PacketInfo packet) {
        int hash = computeHash(packet);
        return Math.abs(hash) % fastPaths.size();
    }

    /**
     * Computes a hash from packet fields that form the five-tuple.
     * Uses the same fields regardless of packet direction by combining
     * src+dst so the hash is the same for both directions.
     */
    private int computeHash(PacketInfo packet) {
        int hash = 17;
        if (packet.getSrcIp() != null) hash = hash * 31 + packet.getSrcIp().hashCode();
        if (packet.getDstIp() != null) hash = hash * 31 + packet.getDstIp().hashCode();
        hash = hash * 31 + packet.getSrcPort();
        hash = hash * 31 + packet.getDstPort();
        hash = hash * 31 + packet.getProtocol();
        return hash;
    }

    // ---- Accessors ----
    public int getId() { return id; }
    public BlockingQueue<PacketInfo> getInputQueue() { return inputQueue; }
    public long getDispatchedCount() { return dispatchedCount.get(); }
}
