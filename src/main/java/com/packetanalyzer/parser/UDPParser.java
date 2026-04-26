package com.packetanalyzer.parser;

import com.packetanalyzer.model.PacketInfo;
import com.packetanalyzer.utils.ByteUtils;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Parses UDP datagram headers from raw packet data.
 *
 * UDP Header Structure (8 bytes):
 * +--------+--------+--------+--------+
 * |  Source Port     | Destination Port|
 * +--------+--------+--------+--------+
 * |   Length         |   Checksum      |
 * +--------+--------+--------+--------+
 */
public class UDPParser {

    private static final Logger logger = LoggerFactory.getLogger(UDPParser.class);

    /** Fixed UDP header size */
    public static final int UDP_HEADER_SIZE = 8;

    /**
     * Parses the UDP header from raw packet data starting at the given offset.
     *
     * @param rawData the complete raw packet bytes
     * @param offset  the byte offset where the UDP header begins
     * @param packetInfo the PacketInfo object to populate
     * @return the offset where the UDP payload begins, or -1 on failure
     */
    public int parse(byte[] rawData, int offset, PacketInfo packetInfo) {
        if (!ByteUtils.hasEnoughBytes(rawData, offset, UDP_HEADER_SIZE)) {
            logger.warn("Packet too short for UDP header at offset {}", offset);
            return -1;
        }

        try {
            // Source Port (bytes 0-1)
            int srcPort = ByteUtils.readUint16(rawData, offset);
            packetInfo.setSrcPort(srcPort);

            // Destination Port (bytes 2-3)
            int dstPort = ByteUtils.readUint16(rawData, offset + 2);
            packetInfo.setDstPort(dstPort);

            // Length (bytes 4-5) - includes header
            int udpLength = ByteUtils.readUint16(rawData, offset + 4);

            // Extract UDP payload
            int payloadOffset = offset + UDP_HEADER_SIZE;
            int payloadLength = udpLength - UDP_HEADER_SIZE;

            if (payloadLength > 0 && payloadOffset + payloadLength <= rawData.length) {
                byte[] payload = ByteUtils.extractBytes(rawData, payloadOffset, payloadLength);
                packetInfo.setPayload(payload);
            } else if (payloadLength > 0 && payloadOffset < rawData.length) {
                // Truncated packet: take what we can
                byte[] payload = ByteUtils.extractBytes(rawData, payloadOffset,
                        rawData.length - payloadOffset);
                packetInfo.setPayload(payload);
            }

            logger.debug("UDP: {}:{} -> {}:{} | Length: {}",
                    packetInfo.getSrcIp(), srcPort, packetInfo.getDstIp(), dstPort, udpLength);

            return payloadOffset;

        } catch (Exception e) {
            logger.error("Error parsing UDP header: {}", e.getMessage());
            return -1;
        }
    }
}
