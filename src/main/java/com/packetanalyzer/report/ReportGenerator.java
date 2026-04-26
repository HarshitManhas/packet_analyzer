package com.packetanalyzer.report;

import com.packetanalyzer.engine.DPIEngine;
import com.packetanalyzer.engine.FastPath;
import com.packetanalyzer.engine.LoadBalancer;
import com.packetanalyzer.model.AppType;
import com.packetanalyzer.model.Connection;
import com.packetanalyzer.model.DPIStats;
import com.packetanalyzer.model.FiveTuple;
import com.packetanalyzer.utils.PacketUtils;

import java.util.*;
import java.util.concurrent.atomic.AtomicInteger;

/**
 * Generates formatted reports from DPI statistics.
 * Matches the C++ report output format with thread statistics.
 */
public class ReportGenerator {

    /**
     * Generates a report with per-thread stats (LB/FP architecture).
     */
    public void generateConsoleReport(DPIStats stats, DPIEngine engine) {
        StringBuilder sb = new StringBuilder();
        String line = "═".repeat(62);

        sb.append("\n╔").append(line).append("╗");
        sb.append("\n║                      PROCESSING REPORT                        ║");
        sb.append("\n╠").append(line).append("╣");

        // Packet summary
        long totalPackets = engine.getReaderPacketCount();
        long totalForwarded = 0;
        long totalDropped = 0;
        long totalBytes = 0;
        int tcpPackets = 0;
        int udpPackets = 0;

        // Aggregate from FPs
        Map<AppType, Integer> appCounts = new LinkedHashMap<>();
        Map<String, Integer> domainMap = new LinkedHashMap<>();
        List<Connection> allConnections = new ArrayList<>();

        for (FastPath fp : engine.getFastPaths()) {
            totalForwarded += fp.getForwardedCount();
            totalDropped += fp.getDroppedCount();

            for (Map.Entry<FiveTuple, Connection> entry : fp.getFlows().entrySet()) {
                Connection conn = entry.getValue();
                FiveTuple tuple = entry.getKey();
                totalBytes += conn.getTotalBytes();
                allConnections.add(conn);

                if (tuple.getProtocol() == 6) tcpPackets += conn.getPacketCount();
                else if (tuple.getProtocol() == 17) udpPackets += conn.getPacketCount();

                // App type counts
                appCounts.merge(conn.getAppType(), conn.getPacketCount(), Integer::sum);

                // Domain counts
                if (conn.getDetectedDomain() != null) {
                    domainMap.merge(conn.getDetectedDomain(), conn.getPacketCount(), Integer::sum);
                }
            }
        }

        sb.append(String.format("\n║ Total Packets:              %6d                              ║", totalPackets));
        sb.append(String.format("\n║ Total Bytes:              %8s                              ║", PacketUtils.formatBytes(totalBytes)));
        sb.append(String.format("\n║ TCP Packets:                %6d                              ║", tcpPackets));
        sb.append(String.format("\n║ UDP Packets:                %6d                              ║", udpPackets));
        sb.append("\n╠").append(line).append("╣");
        sb.append(String.format("\n║ Forwarded:                  %6d                              ║", totalForwarded));
        sb.append(String.format("\n║ Dropped:                    %6d                              ║", totalDropped));

        // Thread statistics
        sb.append("\n╠").append(line).append("╣");
        sb.append("\n║ THREAD STATISTICS                                             ║");

        for (LoadBalancer lb : engine.getLoadBalancers()) {
            sb.append(String.format("\n║   LB%d dispatched:           %6d                              ║",
                    lb.getId(), lb.getDispatchedCount()));
        }
        for (FastPath fp : engine.getFastPaths()) {
            sb.append(String.format("\n║   FP%d processed:            %6d                              ║",
                    fp.getId(), fp.getProcessedCount()));
        }

        // Application breakdown
        if (!appCounts.isEmpty()) {
            sb.append("\n╠").append(line).append("╣");
            sb.append("\n║                   APPLICATION BREAKDOWN                       ║");
            sb.append("\n╠").append(line).append("╣");

            long totalClassified = appCounts.values().stream().mapToInt(Integer::intValue).sum();

            appCounts.entrySet().stream()
                    .sorted((a, b) -> b.getValue() - a.getValue())
                    .forEach(entry -> {
                        double pct = totalClassified > 0 ? (entry.getValue() * 100.0 / totalClassified) : 0;
                        int bars = (int) (pct / 5);
                        String barStr = "#".repeat(Math.max(0, bars));

                        // Check if this app is blocked
                        boolean blocked = engine.getRuleManager().getBlockedApps().contains(entry.getKey());
                        String blockedStr = blocked ? " (BLOCKED)" : "";

                        sb.append(String.format("\n║ %-18s %4d %5.1f%% %-15s%s",
                                entry.getKey().getName(),
                                entry.getValue(),
                                pct,
                                barStr,
                                blockedStr));
                        // Pad to box width
                        int currentLen = sb.length() - sb.lastIndexOf("\n") - 1;
                        if (currentLen < 63) {
                            sb.append(" ".repeat(63 - currentLen));
                        }
                        sb.append("║");
                    });
        }

        sb.append("\n╚").append(line).append("╝");

        // Detected domains (outside the box, matching C++ format)
        if (!domainMap.isEmpty()) {
            sb.append("\n\n[Detected Domains/SNIs]");
            domainMap.entrySet().stream()
                    .sorted((a, b) -> b.getValue() - a.getValue())
                    .forEach(entry -> {
                        // Find the app type for this domain
                        String appName = "Unknown";
                        for (Connection conn : allConnections) {
                            if (entry.getKey().equals(conn.getDetectedDomain())
                                    && conn.getAppType() != AppType.UNKNOWN) {
                                appName = conn.getAppType().getName();
                                break;
                            }
                        }
                        sb.append(String.format("\n  - %s -> %s", entry.getKey(), appName));
                    });
        }

        // Connection summary
        sb.append(String.format("\n\n[Connections] Total: %d | Flows: %d",
                allConnections.size(), allConnections.size()));

        // Top connections
        if (!allConnections.isEmpty()) {
            sb.append("\n\n[Top Connections by packet count]");
            allConnections.stream()
                    .sorted((a, b) -> b.getPacketCount() - a.getPacketCount())
                    .limit(10)
                    .forEach(conn -> {
                        sb.append(String.format("\n  %s", conn.getFiveTuple()));
                        sb.append(String.format("\n    Packets: %d | Bytes: %s | State: %s",
                                conn.getPacketCount(),
                                PacketUtils.formatBytes(conn.getTotalBytes()),
                                conn.getState()));
                        if (conn.getDetectedDomain() != null) {
                            sb.append(String.format(" | Domain: %s", conn.getDetectedDomain()));
                        }
                        if (conn.getAppType() != AppType.UNKNOWN) {
                            sb.append(String.format(" | App: %s", conn.getAppType().getName()));
                        }
                    });
        }

        sb.append("\n");

        System.out.println(sb);
    }

    /**
     * Legacy report method for non-LB/FP usage (backward compatibility).
     */
    public void generateConsoleReport(DPIStats stats,
                                       com.packetanalyzer.engine.FlowManager flowManager,
                                       com.packetanalyzer.engine.ConnectionTracker connectionTracker) {
        StringBuilder sb = new StringBuilder();
        String line = "=".repeat(55);

        sb.append("\n").append(line);
        sb.append("\n          PACKET ANALYZER - DPI REPORT");
        sb.append("\n").append(line);

        sb.append("\n\n--- Packet Summary ---");
        sb.append(String.format("\n  Total Packets:       %d", stats.getTotalPackets()));
        sb.append(String.format("\n  TCP Packets:         %d", stats.getTcpPackets()));
        sb.append(String.format("\n  UDP Packets:         %d", stats.getUdpPackets()));
        sb.append(String.format("\n  Total Bytes:         %s", PacketUtils.formatBytes(stats.getTotalBytes())));

        sb.append("\n\n--- Filtering Summary ---");
        sb.append(String.format("\n  Forwarded Packets:   %d", stats.getForwardedPackets()));
        sb.append(String.format("\n  Dropped Packets:     %d", stats.getDroppedPackets()));

        Map<AppType, AtomicInteger> appCounts = stats.getAppTypeCounts();
        if (!appCounts.isEmpty()) {
            sb.append("\n\n--- Application Classification ---");
            appCounts.entrySet().stream()
                    .sorted((a, b) -> b.getValue().get() - a.getValue().get())
                    .forEach(entry -> sb.append(String.format("\n  %-20s %d packets",
                            entry.getKey().getName(), entry.getValue().get())));
        }

        Map<String, AtomicInteger> domainCounts = stats.getDomainCounts();
        if (!domainCounts.isEmpty()) {
            sb.append("\n\n--- Detected Domains ---");
            domainCounts.entrySet().stream()
                    .sorted((a, b) -> b.getValue().get() - a.getValue().get())
                    .forEach(entry -> sb.append(String.format("\n  - %s (%d packets)",
                            entry.getKey(), entry.getValue().get())));
        }

        if (flowManager != null) {
            sb.append(String.format("\n\n--- Flows: %d ---", flowManager.getFlowCount()));
        }
        if (connectionTracker != null) {
            sb.append(String.format("\n--- Connections: %d (Active: %d) ---",
                    connectionTracker.getTotalConnectionCount(),
                    connectionTracker.getActiveConnectionCount()));
        }

        sb.append("\n\n").append(line).append("\n");
        System.out.println(sb);
    }
}
