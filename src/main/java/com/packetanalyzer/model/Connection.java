package com.packetanalyzer.model;

import java.time.Instant;
import java.util.ArrayList;
import java.util.List;

/**
 * Represents a tracked network connection, aggregating packets belonging
 * to the same flow (identified by a normalized FiveTuple).
 */
public class Connection {

    public enum State {
        NEW,
        ESTABLISHED,
        CLOSING,
        CLOSED,
        RESET
    }

    private final FiveTuple fiveTuple;
    private State state;
    private Instant startTime;
    private Instant lastActivityTime;
    private long totalBytes;
    private int packetCount;
    private int forwardPackets;
    private int backwardPackets;
    private long forwardBytes;
    private long backwardBytes;
    private AppType appType = AppType.UNKNOWN;
    private String detectedDomain;
    private final List<String> detectedDomains = new ArrayList<>();

    public Connection(FiveTuple fiveTuple) {
        this.fiveTuple = fiveTuple;
        this.state = State.NEW;
        this.startTime = Instant.now();
        this.lastActivityTime = this.startTime;
    }

    /**
     * Updates connection state with a new packet belonging to this flow.
     * Synchronized to ensure thread-safety during concurrent processing.
     */
    public synchronized void addPacket(PacketInfo packet) {
        packetCount++;
        totalBytes += packet.getLength();
        lastActivityTime = packet.getTimestamp() != null ? packet.getTimestamp() : Instant.now();

        if (startTime == null) {
            startTime = lastActivityTime;
        }

        // Determine direction: forward if src matches the original flow src
        if (packet.getFiveTuple() != null &&
            packet.getFiveTuple().getSrcIp().equals(fiveTuple.getSrcIp())) {
            forwardPackets++;
            forwardBytes += packet.getLength();
        } else {
            backwardPackets++;
            backwardBytes += packet.getLength();
        }

        // Update application type if detected
        if (packet.getAppType() != AppType.UNKNOWN) {
            this.appType = packet.getAppType();
        }

        // Track detected domains
        if (packet.getDetectedDomain() != null && !packet.getDetectedDomain().isEmpty()) {
            this.detectedDomain = packet.getDetectedDomain();
            if (!detectedDomains.contains(packet.getDetectedDomain())) {
                detectedDomains.add(packet.getDetectedDomain());
            }
        }

        // Update TCP connection state
        if (packet.isTcp()) {
            updateTcpState(packet);
        }
    }

    private void updateTcpState(PacketInfo packet) {
        if (packet.isRstFlag()) {
            state = State.RESET;
        } else if (packet.isSynFlag() && !packet.isAckFlag()) {
            state = State.NEW;
        } else if (packet.isSynFlag() && packet.isAckFlag()) {
            state = State.ESTABLISHED;
        } else if (packet.isFinFlag()) {
            state = (state == State.CLOSING) ? State.CLOSED : State.CLOSING;
        } else if (state == State.NEW && packet.isAckFlag()) {
            state = State.ESTABLISHED;
        }
    }

    /**
     * Returns the duration of the connection in milliseconds.
     */
    public long getDurationMs() {
        if (startTime == null || lastActivityTime == null) return 0;
        return lastActivityTime.toEpochMilli() - startTime.toEpochMilli();
    }

    // ---- Getters ----

    public FiveTuple getFiveTuple() {
        return fiveTuple;
    }

    public State getState() {
        return state;
    }

    public Instant getStartTime() {
        return startTime;
    }

    public Instant getLastActivityTime() {
        return lastActivityTime;
    }

    public long getTotalBytes() {
        return totalBytes;
    }

    public int getPacketCount() {
        return packetCount;
    }

    public int getForwardPackets() {
        return forwardPackets;
    }

    public int getBackwardPackets() {
        return backwardPackets;
    }

    public long getForwardBytes() {
        return forwardBytes;
    }

    public long getBackwardBytes() {
        return backwardBytes;
    }

    public AppType getAppType() {
        return appType;
    }

    public String getDetectedDomain() {
        return detectedDomain;
    }

    public List<String> getDetectedDomains() {
        return detectedDomains;
    }

    @Override
    public String toString() {
        return String.format("Connection[%s | state=%s | packets=%d | bytes=%d | app=%s | domain=%s]",
                fiveTuple, state, packetCount, totalBytes,
                appType.getName(), detectedDomain != null ? detectedDomain : "N/A");
    }
}
