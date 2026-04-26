package com.packetanalyzer.parser;

import com.packetanalyzer.model.PacketInfo;
import com.packetanalyzer.utils.ByteUtils;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Parses TCP segment headers from raw packet data.
 *
 * TCP Header Structure (20-60 bytes):
 * +--------+--------+--------+--------+
 * |  Source Port     | Destination Port|
 * +--------+--------+--------+--------+
 * |         Sequence Number            |
 * +--------+--------+--------+--------+
 * |       Acknowledgment Number        |
 * +--------+--------+--------+--------+
 * |Offset|Res|Flags |  Window Size    |
 * +--------+--------+--------+--------+
 * |   Checksum      | Urgent Pointer  |
 * +--------+--------+--------+--------+
 * |   Options (if Data Offset > 5)    |
 * +-----------------------------------+
 */
public class TCPParser {

    private static final Logger logger = LoggerFactory.getLogger(TCPParser.class);

    /** Minimum TCP header size (no options) */
    public static final int MIN_TCP_HEADER_SIZE = 20;

    /** TCP flag bit masks */
    private static final int FLAG_FIN = 0x01;
    private static final int FLAG_SYN = 0x02;
    private static final int FLAG_RST = 0x04;
    private static final int FLAG_PSH = 0x08;
    private static final int FLAG_ACK = 0x10;

    /**
     * Parses the TCP header from raw packet data starting at the given offset.
     *
     * @param rawData the complete raw packet bytes
     * @param offset  the byte offset where the TCP header begins
     * @param packetInfo the PacketInfo object to populate
     * @return the offset where the TCP payload begins, or -1 on failure
     */
    public int parse(byte[] rawData, int offset, PacketInfo packetInfo) {
        if (!ByteUtils.hasEnoughBytes(rawData, offset, MIN_TCP_HEADER_SIZE)) {
            logger.warn("Packet too short for TCP header at offset {}", offset);
            return -1;
        }

        try {
            // Source Port (bytes 0-1)
            int srcPort = ByteUtils.readUint16(rawData, offset);
            packetInfo.setSrcPort(srcPort);

            // Destination Port (bytes 2-3)
            int dstPort = ByteUtils.readUint16(rawData, offset + 2);
            packetInfo.setDstPort(dstPort);

            // Sequence Number (bytes 4-7)
            long seqNum = ByteUtils.readUint32(rawData, offset + 4);
            packetInfo.setSequenceNumber(seqNum);

            // Acknowledgment Number (bytes 8-11)
            long ackNum = ByteUtils.readUint32(rawData, offset + 8);
            packetInfo.setAckNumber(ackNum);

            // Data Offset + Flags (bytes 12-13)
            int dataOffsetFlags = ByteUtils.readUint16(rawData, offset + 12);
            int dataOffset = ((dataOffsetFlags >> 12) & 0x0F) * 4; // In 32-bit words -> bytes
            int flags = dataOffsetFlags & 0x3F;

            packetInfo.setTcpHeaderLength(dataOffset);
            packetInfo.setFinFlag((flags & FLAG_FIN) != 0);
            packetInfo.setSynFlag((flags & FLAG_SYN) != 0);
            packetInfo.setRstFlag((flags & FLAG_RST) != 0);
            packetInfo.setPshFlag((flags & FLAG_PSH) != 0);
            packetInfo.setAckFlag((flags & FLAG_ACK) != 0);

            // Window Size (bytes 14-15)
            int windowSize = ByteUtils.readUint16(rawData, offset + 14);
            packetInfo.setWindowSize(windowSize);

            // Extract TCP payload
            int payloadOffset = offset + dataOffset;
            if (payloadOffset < rawData.length) {
                byte[] payload = ByteUtils.extractBytes(rawData, payloadOffset,
                        rawData.length - payloadOffset);
                packetInfo.setPayload(payload);
            }

            logger.debug("TCP: {}:{} -> {}:{} | Seq: {} | Flags: {} | Win: {}",
                    packetInfo.getSrcIp(), srcPort, packetInfo.getDstIp(), dstPort,
                    seqNum,
                    com.packetanalyzer.utils.PacketUtils.formatTcpFlags(
                            packetInfo.isSynFlag(), packetInfo.isAckFlag(),
                            packetInfo.isFinFlag(), packetInfo.isRstFlag(),
                            packetInfo.isPshFlag()),
                    windowSize);

            return payloadOffset;

        } catch (Exception e) {
            logger.error("Error parsing TCP header: {}", e.getMessage());
            return -1;
        }
    }
}
