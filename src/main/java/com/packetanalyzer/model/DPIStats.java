package com.packetanalyzer.model;

import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicLong;

/**
 * Thread-safe statistics accumulator for DPI processing results.
 * Tracks packet counts, protocol distributions, detected applications, and domains.
 */
public class DPIStats {
    private final AtomicInteger totalPackets = new AtomicInteger(0);
    private final AtomicInteger tcpPackets = new AtomicInteger(0);
    private final AtomicInteger udpPackets = new AtomicInteger(0);
    private final AtomicInteger otherPackets = new AtomicInteger(0);
    private final AtomicInteger droppedPackets = new AtomicInteger(0);
    private final AtomicInteger forwardedPackets = new AtomicInteger(0);
    private final AtomicInteger blockedPackets = new AtomicInteger(0);
    private final AtomicLong totalBytes = new AtomicLong(0);
    private final AtomicInteger malformedPackets = new AtomicInteger(0);
    private final AtomicInteger tlsPackets = new AtomicInteger(0);

    private final Map<AppType, AtomicInteger> appTypeCounts = new ConcurrentHashMap<>();
    private final Map<String, AtomicInteger> domainCounts = new ConcurrentHashMap<>();
    private final Map<String, AtomicInteger> protocolCounts = new ConcurrentHashMap<>();

    public void recordPacket(PacketInfo packet) {
        totalPackets.incrementAndGet();
        totalBytes.addAndGet(packet.getLength());

        // Protocol counting
        if (packet.isTcp()) {
            tcpPackets.incrementAndGet();
        } else if (packet.isUdp()) {
            udpPackets.incrementAndGet();
        } else {
            otherPackets.incrementAndGet();
        }

        // Blocked/forwarded tracking
        if (packet.isBlocked()) {
            blockedPackets.incrementAndGet();
            droppedPackets.incrementAndGet();
        } else {
            forwardedPackets.incrementAndGet();
        }

        // Application type tracking
        appTypeCounts.computeIfAbsent(packet.getAppType(), k -> new AtomicInteger(0))
                     .incrementAndGet();

        // Domain tracking
        if (packet.getDetectedDomain() != null && !packet.getDetectedDomain().isEmpty()) {
            domainCounts.computeIfAbsent(packet.getDetectedDomain(), k -> new AtomicInteger(0))
                        .incrementAndGet();
        }

        // TLS tracking
        if (packet.getTlsVersion() != null) {
            tlsPackets.incrementAndGet();
        }
    }

    public void recordMalformed() {
        malformedPackets.incrementAndGet();
        droppedPackets.incrementAndGet();
        totalPackets.incrementAndGet();
    }

    // ---- Getters ----

    public int getTotalPackets() {
        return totalPackets.get();
    }

    public int getTcpPackets() {
        return tcpPackets.get();
    }

    public int getUdpPackets() {
        return udpPackets.get();
    }

    public int getOtherPackets() {
        return otherPackets.get();
    }

    public int getDroppedPackets() {
        return droppedPackets.get();
    }

    public int getForwardedPackets() {
        return forwardedPackets.get();
    }

    public int getBlockedPackets() {
        return blockedPackets.get();
    }

    public long getTotalBytes() {
        return totalBytes.get();
    }

    public int getMalformedPackets() {
        return malformedPackets.get();
    }

    public int getTlsPackets() {
        return tlsPackets.get();
    }

    public Map<AppType, AtomicInteger> getAppTypeCounts() {
        return appTypeCounts;
    }

    public Map<String, AtomicInteger> getDomainCounts() {
        return domainCounts;
    }

    public Map<String, AtomicInteger> getProtocolCounts() {
        return protocolCounts;
    }

    @Override
    public String toString() {
        return String.format(
            "DPIStats[total=%d, tcp=%d, udp=%d, dropped=%d, forwarded=%d, bytes=%d]",
            totalPackets.get(), tcpPackets.get(), udpPackets.get(),
            droppedPackets.get(), forwardedPackets.get(), totalBytes.get());
    }
}
