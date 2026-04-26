package com.packetanalyzer.parser;

import com.packetanalyzer.model.PacketInfo;
import com.packetanalyzer.utils.ByteUtils;
import com.packetanalyzer.utils.IPUtils;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Parses IPv4 headers from raw packet data.
 *
 * IPv4 Header Structure (20-60 bytes):
 * +--------+--------+--------+--------+
 * |Ver| IHL|  DSCP  | Total Length    |
 * +--------+--------+--------+--------+
 * | Identification  |Flags|Frag Offset|
 * +--------+--------+--------+--------+
 * |  TTL   |Protocol|  Header Checksum|
 * +--------+--------+--------+--------+
 * |         Source IP Address          |
 * +--------+--------+--------+--------+
 * |       Destination IP Address       |
 * +--------+--------+--------+--------+
 * |   Options (if IHL > 5) ...        |
 * +-----------------------------------+
 */
public class IPParser {

    private static final Logger logger = LoggerFactory.getLogger(IPParser.class);

    /** Minimum IPv4 header size (no options) */
    public static final int MIN_IP_HEADER_SIZE = 20;

    /** Protocol numbers */
    public static final int PROTO_ICMP = 1;
    public static final int PROTO_TCP  = 6;
    public static final int PROTO_UDP  = 17;

    /**
     * Parses the IPv4 header from raw packet data starting at the given offset.
     *
     * @param rawData the complete raw packet bytes
     * @param offset  the byte offset where the IP header begins
     * @param packetInfo the PacketInfo object to populate
     * @return the offset where the IP payload (transport layer) begins, or -1 on failure
     */
    public int parse(byte[] rawData, int offset, PacketInfo packetInfo) {
        if (!ByteUtils.hasEnoughBytes(rawData, offset, MIN_IP_HEADER_SIZE)) {
            logger.warn("Packet too short for IP header at offset {}", offset);
            return -1;
        }

        try {
            // Version and IHL (byte 0)
            int versionIhl = ByteUtils.readUint8(rawData, offset);
            int version = (versionIhl >> 4) & 0x0F;
            int ihl = (versionIhl & 0x0F) * 4; // IHL in 32-bit words -> bytes

            if (version != 4) {
                logger.warn("Not an IPv4 packet (version={})", version);
                return -1;
            }

            if (ihl < MIN_IP_HEADER_SIZE) {
                logger.warn("Invalid IP header length: {} bytes", ihl);
                return -1;
            }

            packetInfo.setIpVersion(version);
            packetInfo.setIpHeaderLength(ihl);

            // Total Length (bytes 2-3)
            int totalLength = ByteUtils.readUint16(rawData, offset + 2);
            packetInfo.setTotalLength(totalLength);

            // TTL (byte 8)
            int ttl = ByteUtils.readUint8(rawData, offset + 8);
            packetInfo.setTtl(ttl);

            // Protocol (byte 9)
            int protocol = ByteUtils.readUint8(rawData, offset + 9);
            packetInfo.setProtocol(protocol);

            // Source IP (bytes 12-15)
            String srcIp = IPUtils.bytesToIpv4(rawData, offset + 12);
            packetInfo.setSrcIp(srcIp);

            // Destination IP (bytes 16-19)
            String dstIp = IPUtils.bytesToIpv4(rawData, offset + 16);
            packetInfo.setDstIp(dstIp);

            logger.debug("IPv4: {} -> {} | Protocol: {} | TTL: {} | Length: {}",
                    srcIp, dstIp, IPUtils.getProtocolName(protocol), ttl, totalLength);

            return offset + ihl;

        } catch (Exception e) {
            logger.error("Error parsing IP header: {}", e.getMessage());
            return -1;
        }
    }
}
