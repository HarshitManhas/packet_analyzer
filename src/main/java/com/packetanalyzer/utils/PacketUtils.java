package com.packetanalyzer.utils;

import com.packetanalyzer.model.AppType;

/**
 * Utility class for packet-level operations including well-known port
 * detection and application classification based on port numbers.
 */
public final class PacketUtils {

    private PacketUtils() {
        // Utility class, prevent instantiation
    }

    /**
     * Determines the application type based on well-known port numbers.
     * Used as a fallback when DPI signature detection does not identify the traffic.
     */
    public static AppType classifyByPort(int srcPort, int dstPort) {
        int port = Math.min(srcPort, dstPort); // Use the well-known port (typically lower)

        return switch (port) {
            case 80 -> AppType.HTTP;
            case 443 -> AppType.HTTPS;
            case 53 -> AppType.DNS;
            case 22 -> AppType.SSH;
            case 21, 20 -> AppType.FTP;
            case 25, 587 -> AppType.SMTP;
            case 143, 993 -> AppType.IMAP;
            case 110, 995 -> AppType.POP3;
            case 67, 68 -> AppType.DHCP;
            case 123 -> AppType.NTP;
            default -> AppType.UNKNOWN;
        };
    }

    /**
     * Checks if the given port is a well-known port (0-1023).
     */
    public static boolean isWellKnownPort(int port) {
        return port >= 0 && port <= 1023;
    }

    /**
     * Checks if the given port is a registered port (1024-49151).
     */
    public static boolean isRegisteredPort(int port) {
        return port >= 1024 && port <= 49151;
    }

    /**
     * Checks if the given port is an ephemeral/dynamic port (49152-65535).
     */
    public static boolean isEphemeralPort(int port) {
        return port >= 49152 && port <= 65535;
    }

    /**
     * Formats a byte count into a human-readable size string.
     */
    public static String formatBytes(long bytes) {
        if (bytes < 1024) return bytes + " B";
        if (bytes < 1024 * 1024) return String.format("%.2f KB", bytes / 1024.0);
        if (bytes < 1024 * 1024 * 1024) return String.format("%.2f MB", bytes / (1024.0 * 1024));
        return String.format("%.2f GB", bytes / (1024.0 * 1024 * 1024));
    }

    /**
     * Returns a human-readable description of EtherType.
     */
    public static String getEtherTypeName(int etherType) {
        return switch (etherType) {
            case 0x0800 -> "IPv4";
            case 0x0806 -> "ARP";
            case 0x86DD -> "IPv6";
            case 0x8100 -> "VLAN (802.1Q)";
            case 0x8847 -> "MPLS Unicast";
            case 0x8848 -> "MPLS Multicast";
            case 0x88CC -> "LLDP";
            default -> String.format("Unknown (0x%04x)", etherType);
        };
    }

    /**
     * Returns TCP flag string representation.
     */
    public static String formatTcpFlags(boolean syn, boolean ack, boolean fin,
                                         boolean rst, boolean psh) {
        StringBuilder sb = new StringBuilder("[");
        if (syn) sb.append("SYN ");
        if (ack) sb.append("ACK ");
        if (fin) sb.append("FIN ");
        if (rst) sb.append("RST ");
        if (psh) sb.append("PSH ");
        if (sb.length() > 1) sb.setLength(sb.length() - 1); // Remove trailing space
        sb.append("]");
        return sb.toString();
    }
}
