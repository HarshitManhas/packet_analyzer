package com.packetanalyzer.model;

import java.time.Instant;

/**
 * Container for all parsed information extracted from a single network packet.
 * Populated progressively as the packet passes through each parser layer.
 */
public class PacketInfo {
    // Raw packet data
    private byte[] rawData;
    private int length;
    private Instant timestamp;

    // Ethernet layer
    private String srcMac;
    private String dstMac;
    private int etherType;

    // IP layer
    private String srcIp;
    private String dstIp;
    private int ipVersion;
    private int protocol;  // 6 = TCP, 17 = UDP
    private int ttl;
    private int ipHeaderLength;
    private int totalLength;

    // Transport layer (TCP/UDP)
    private int srcPort;
    private int dstPort;

    // TCP-specific fields
    private long sequenceNumber;
    private long ackNumber;
    private boolean synFlag;
    private boolean ackFlag;
    private boolean finFlag;
    private boolean rstFlag;
    private boolean pshFlag;
    private int tcpHeaderLength;
    private int windowSize;

    // Payload
    private byte[] payload;
    private int payloadLength;

    // DPI results
    private AppType appType = AppType.UNKNOWN;
    private String detectedDomain;
    private String tlsVersion;

    // Flow tracking
    private FiveTuple fiveTuple;

    // Filtering result
    private boolean blocked = false;
    private String blockReason;

    // ---- Getters and Setters ----

    public byte[] getRawData() {
        return rawData;
    }

    public void setRawData(byte[] rawData) {
        this.rawData = rawData;
    }

    public int getLength() {
        return length;
    }

    public void setLength(int length) {
        this.length = length;
    }

    public Instant getTimestamp() {
        return timestamp;
    }

    public void setTimestamp(Instant timestamp) {
        this.timestamp = timestamp;
    }

    public String getSrcMac() {
        return srcMac;
    }

    public void setSrcMac(String srcMac) {
        this.srcMac = srcMac;
    }

    public String getDstMac() {
        return dstMac;
    }

    public void setDstMac(String dstMac) {
        this.dstMac = dstMac;
    }

    public int getEtherType() {
        return etherType;
    }

    public void setEtherType(int etherType) {
        this.etherType = etherType;
    }

    public String getSrcIp() {
        return srcIp;
    }

    public void setSrcIp(String srcIp) {
        this.srcIp = srcIp;
    }

    public String getDstIp() {
        return dstIp;
    }

    public void setDstIp(String dstIp) {
        this.dstIp = dstIp;
    }

    public int getIpVersion() {
        return ipVersion;
    }

    public void setIpVersion(int ipVersion) {
        this.ipVersion = ipVersion;
    }

    public int getProtocol() {
        return protocol;
    }

    public void setProtocol(int protocol) {
        this.protocol = protocol;
    }

    public int getTtl() {
        return ttl;
    }

    public void setTtl(int ttl) {
        this.ttl = ttl;
    }

    public int getIpHeaderLength() {
        return ipHeaderLength;
    }

    public void setIpHeaderLength(int ipHeaderLength) {
        this.ipHeaderLength = ipHeaderLength;
    }

    public int getTotalLength() {
        return totalLength;
    }

    public void setTotalLength(int totalLength) {
        this.totalLength = totalLength;
    }

    public int getSrcPort() {
        return srcPort;
    }

    public void setSrcPort(int srcPort) {
        this.srcPort = srcPort;
    }

    public int getDstPort() {
        return dstPort;
    }

    public void setDstPort(int dstPort) {
        this.dstPort = dstPort;
    }

    public long getSequenceNumber() {
        return sequenceNumber;
    }

    public void setSequenceNumber(long sequenceNumber) {
        this.sequenceNumber = sequenceNumber;
    }

    public long getAckNumber() {
        return ackNumber;
    }

    public void setAckNumber(long ackNumber) {
        this.ackNumber = ackNumber;
    }

    public boolean isSynFlag() {
        return synFlag;
    }

    public void setSynFlag(boolean synFlag) {
        this.synFlag = synFlag;
    }

    public boolean isAckFlag() {
        return ackFlag;
    }

    public void setAckFlag(boolean ackFlag) {
        this.ackFlag = ackFlag;
    }

    public boolean isFinFlag() {
        return finFlag;
    }

    public void setFinFlag(boolean finFlag) {
        this.finFlag = finFlag;
    }

    public boolean isRstFlag() {
        return rstFlag;
    }

    public void setRstFlag(boolean rstFlag) {
        this.rstFlag = rstFlag;
    }

    public boolean isPshFlag() {
        return pshFlag;
    }

    public void setPshFlag(boolean pshFlag) {
        this.pshFlag = pshFlag;
    }

    public int getTcpHeaderLength() {
        return tcpHeaderLength;
    }

    public void setTcpHeaderLength(int tcpHeaderLength) {
        this.tcpHeaderLength = tcpHeaderLength;
    }

    public int getWindowSize() {
        return windowSize;
    }

    public void setWindowSize(int windowSize) {
        this.windowSize = windowSize;
    }

    public byte[] getPayload() {
        return payload;
    }

    public void setPayload(byte[] payload) {
        this.payload = payload;
        this.payloadLength = (payload != null) ? payload.length : 0;
    }

    public int getPayloadLength() {
        return payloadLength;
    }

    public AppType getAppType() {
        return appType;
    }

    public void setAppType(AppType appType) {
        this.appType = appType;
    }

    public String getDetectedDomain() {
        return detectedDomain;
    }

    public void setDetectedDomain(String detectedDomain) {
        this.detectedDomain = detectedDomain;
    }

    public String getTlsVersion() {
        return tlsVersion;
    }

    public void setTlsVersion(String tlsVersion) {
        this.tlsVersion = tlsVersion;
    }

    public FiveTuple getFiveTuple() {
        return fiveTuple;
    }

    public void setFiveTuple(FiveTuple fiveTuple) {
        this.fiveTuple = fiveTuple;
    }

    public boolean isBlocked() {
        return blocked;
    }

    public void setBlocked(boolean blocked) {
        this.blocked = blocked;
    }

    public String getBlockReason() {
        return blockReason;
    }

    public void setBlockReason(String blockReason) {
        this.blockReason = blockReason;
    }

    /**
     * Checks if this packet is a TCP packet.
     */
    public boolean isTcp() {
        return protocol == 6;
    }

    /**
     * Checks if this packet is a UDP packet.
     */
    public boolean isUdp() {
        return protocol == 17;
    }

    /**
     * Checks if this packet has payload data.
     */
    public boolean hasPayload() {
        return payload != null && payload.length > 0;
    }

    @Override
    public String toString() {
        StringBuilder sb = new StringBuilder();
        sb.append(String.format("Packet [%d bytes] ", length));
        if (srcIp != null && dstIp != null) {
            sb.append(String.format("%s:%d -> %s:%d ", srcIp, srcPort, dstIp, dstPort));
        }
        if (protocol == 6) sb.append("[TCP] ");
        else if (protocol == 17) sb.append("[UDP] ");
        if (appType != AppType.UNKNOWN) {
            sb.append("[").append(appType.getName()).append("] ");
        }
        if (detectedDomain != null) {
            sb.append("[").append(detectedDomain).append("] ");
        }
        if (blocked) {
            sb.append("[BLOCKED: ").append(blockReason).append("] ");
        }
        return sb.toString().trim();
    }
}
