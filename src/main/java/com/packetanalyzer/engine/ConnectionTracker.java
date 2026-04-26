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
 * Tracks TCP connection states across packets.
 * Maintains per-connection state machines for SYN/FIN/RST transitions.
 */
public class ConnectionTracker {
    private static final Logger logger = LoggerFactory.getLogger(ConnectionTracker.class);
    private final Map<FiveTuple, Connection> connections = new ConcurrentHashMap<>();

    /**
     * Updates connection tracking state for a given packet.
     */
    public Connection track(PacketInfo packet) {
        if (packet.getFiveTuple() == null) return null;

        FiveTuple key = packet.getFiveTuple().normalized();
        Connection conn = connections.computeIfAbsent(key, Connection::new);
        conn.addPacket(packet);

        logger.debug("Connection {} state: {}", key, conn.getState());
        return conn;
    }

    public Connection getConnection(FiveTuple normalized) {
        return connections.get(normalized);
    }

    public Collection<Connection> getAllConnections() {
        return connections.values();
    }

    public int getActiveConnectionCount() {
        return (int) connections.values().stream()
            .filter(c -> c.getState() == Connection.State.ESTABLISHED || c.getState() == Connection.State.NEW)
            .count();
    }

    public int getTotalConnectionCount() {
        return connections.size();
    }

    public void clear() {
        connections.clear();
    }
}
