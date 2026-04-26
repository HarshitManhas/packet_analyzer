package com.packetanalyzer.engine;

import com.packetanalyzer.model.Connection;
import com.packetanalyzer.model.FiveTuple;
import com.packetanalyzer.model.PacketInfo;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.Collection;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

/**
 * Manages flow tracking using normalized FiveTuples.
 * Groups packets into bidirectional flows.
 */
public class FlowManager {
    private static final Logger logger = LoggerFactory.getLogger(FlowManager.class);
    private final Map<FiveTuple, Connection> flows = new ConcurrentHashMap<>();

    /**
     * Assigns a FiveTuple to the packet and tracks it in a flow.
     */
    public Connection trackPacket(PacketInfo packet) {
        if (packet.getSrcIp() == null || packet.getDstIp() == null) {
            return null;
        }

        FiveTuple tuple = new FiveTuple(
            packet.getSrcIp(), packet.getDstIp(),
            packet.getSrcPort(), packet.getDstPort(),
            packet.getProtocol()
        );
        packet.setFiveTuple(tuple);

        FiveTuple normalized = tuple.normalized();
        Connection conn = flows.computeIfAbsent(normalized, Connection::new);
        conn.addPacket(packet);

        logger.debug("Flow tracked: {} (total packets in flow: {})", normalized, conn.getPacketCount());
        return conn;
    }

    public Collection<Connection> getAllFlows() {
        return flows.values();
    }

    public int getFlowCount() {
        return flows.size();
    }

    public Connection getFlow(FiveTuple normalized) {
        return flows.get(normalized);
    }

    public void clear() {
        flows.clear();
    }
}
