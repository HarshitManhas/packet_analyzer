package com.packetanalyzer.report;

import com.packetanalyzer.model.DPIStats;
import com.packetanalyzer.model.PacketInfo;

/**
 * Collects statistics from processed packets into a DPIStats instance.
 */
public class StatsCollector {
    private final DPIStats stats = new DPIStats();

    /**
     * Records a successfully parsed packet.
     */
    public void recordPacket(PacketInfo packet) {
        stats.recordPacket(packet);
    }

    /**
     * Records a malformed/unparseable packet.
     */
    public void recordMalformed() {
        stats.recordMalformed();
    }

    /**
     * Returns the accumulated statistics.
     */
    public DPIStats getStats() {
        return stats;
    }
}
