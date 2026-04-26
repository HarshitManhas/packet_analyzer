package com.packetanalyzer.utils;

/**
 * Utility class for IP address related operations.
 */
public final class IPUtils {

    private IPUtils() {
        // Utility class, prevent instantiation
    }

    /**
     * Converts 4 bytes starting at offset to a dotted-decimal IPv4 string.
     */
    public static String bytesToIpv4(byte[] data, int offset) {
        if (data == null || offset + 3 >= data.length) {
            return "0.0.0.0";
        }
        return String.format("%d.%d.%d.%d",
                data[offset] & 0xFF,
                data[offset + 1] & 0xFF,
                data[offset + 2] & 0xFF,
                data[offset + 3] & 0xFF);
    }

    /**
     * Converts a dotted-decimal IPv4 string to a 4-byte array.
     */
    public static byte[] ipv4ToBytes(String ip) {
        if (ip == null || ip.isEmpty()) return new byte[4];
        String[] parts = ip.split("\\.");
        if (parts.length != 4) return new byte[4];
        byte[] result = new byte[4];
        for (int i = 0; i < 4; i++) {
            result[i] = (byte) Integer.parseInt(parts[i]);
        }
        return result;
    }

    /**
     * Validates an IPv4 address string.
     */
    public static boolean isValidIpv4(String ip) {
        if (ip == null || ip.isEmpty()) return false;
        String[] parts = ip.split("\\.");
        if (parts.length != 4) return false;
        for (String part : parts) {
            try {
                int value = Integer.parseInt(part);
                if (value < 0 || value > 255) return false;
            } catch (NumberFormatException e) {
                return false;
            }
        }
        return true;
    }

    /**
     * Checks if the IP address is a private/RFC1918 address.
     */
    public static boolean isPrivateAddress(String ip) {
        if (!isValidIpv4(ip)) return false;
        String[] parts = ip.split("\\.");
        int first = Integer.parseInt(parts[0]);
        int second = Integer.parseInt(parts[1]);

        // 10.0.0.0/8
        if (first == 10) return true;
        // 172.16.0.0/12
        if (first == 172 && second >= 16 && second <= 31) return true;
        // 192.168.0.0/16
        if (first == 192 && second == 168) return true;
        // Loopback 127.0.0.0/8
        if (first == 127) return true;

        return false;
    }

    /**
     * Checks if the IP address is a broadcast address.
     */
    public static boolean isBroadcast(String ip) {
        return "255.255.255.255".equals(ip);
    }

    /**
     * Checks if the IP address is a multicast address (224.0.0.0 - 239.255.255.255).
     */
    public static boolean isMulticast(String ip) {
        if (!isValidIpv4(ip)) return false;
        int first = Integer.parseInt(ip.split("\\.")[0]);
        return first >= 224 && first <= 239;
    }

    /**
     * Returns the protocol name for a given protocol number.
     */
    public static String getProtocolName(int protocolNumber) {
        return switch (protocolNumber) {
            case 1 -> "ICMP";
            case 2 -> "IGMP";
            case 6 -> "TCP";
            case 17 -> "UDP";
            case 41 -> "IPv6";
            case 47 -> "GRE";
            case 50 -> "ESP";
            case 51 -> "AH";
            case 58 -> "ICMPv6";
            case 89 -> "OSPF";
            case 132 -> "SCTP";
            default -> "UNKNOWN(" + protocolNumber + ")";
        };
    }
}
