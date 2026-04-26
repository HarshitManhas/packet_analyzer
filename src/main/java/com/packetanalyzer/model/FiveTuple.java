package com.packetanalyzer.model;

import java.util.Objects;

/**
 * Represents a Five-Tuple flow identifier used for connection tracking.
 * A five-tuple uniquely identifies a network flow by:
 * - Source IP address
 * - Destination IP address
 * - Source port
 * - Destination port
 * - Protocol number (6 = TCP, 17 = UDP)
 */
public class FiveTuple {
    private final String srcIp;
    private final String dstIp;
    private final int srcPort;
    private final int dstPort;
    private final int protocol;

    public FiveTuple(String srcIp, String dstIp, int srcPort, int dstPort, int protocol) {
        this.srcIp = srcIp;
        this.dstIp = dstIp;
        this.srcPort = srcPort;
        this.dstPort = dstPort;
        this.protocol = protocol;
    }

    /**
     * Creates the reverse direction five-tuple (swaps src and dst).
     */
    public FiveTuple reverse() {
        return new FiveTuple(dstIp, srcIp, dstPort, srcPort, protocol);
    }

    /**
     * Returns a normalized key so that both directions of a connection
     * map to the same flow. The tuple with the lexicographically smaller
     * source IP (or smaller source port as tiebreaker) is chosen as canonical.
     */
    public FiveTuple normalized() {
        int cmp = srcIp.compareTo(dstIp);
        if (cmp < 0 || (cmp == 0 && srcPort <= dstPort)) {
            return this;
        }
        return reverse();
    }

    public String getSrcIp() {
        return srcIp;
    }

    public String getDstIp() {
        return dstIp;
    }

    public int getSrcPort() {
        return srcPort;
    }

    public int getDstPort() {
        return dstPort;
    }

    public int getProtocol() {
        return protocol;
    }

    public String getProtocolName() {
        return switch (protocol) {
            case 6 -> "TCP";
            case 17 -> "UDP";
            case 1 -> "ICMP";
            default -> "PROTO_" + protocol;
        };
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        FiveTuple fiveTuple = (FiveTuple) o;
        return srcPort == fiveTuple.srcPort &&
               dstPort == fiveTuple.dstPort &&
               protocol == fiveTuple.protocol &&
               Objects.equals(srcIp, fiveTuple.srcIp) &&
               Objects.equals(dstIp, fiveTuple.dstIp);
    }

    @Override
    public int hashCode() {
        return Objects.hash(srcIp, dstIp, srcPort, dstPort, protocol);
    }

    @Override
    public String toString() {
        return String.format("%s:%d -> %s:%d [%s]",
                srcIp, srcPort, dstIp, dstPort, getProtocolName());
    }
}
