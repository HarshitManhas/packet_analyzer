package com.packetanalyzer.parser;

import com.packetanalyzer.model.PacketInfo;
import com.packetanalyzer.utils.ByteUtils;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Parses Ethernet frame headers from raw packet data.
 * 
 * Ethernet II Frame Structure:
 * +------------------+------------------+------------+---------+
 * | Dst MAC (6 bytes)| Src MAC (6 bytes)| Type (2 B) | Payload |
 * +------------------+------------------+------------+---------+
 */
public class EthernetParser {

    private static final Logger logger = LoggerFactory.getLogger(EthernetParser.class);

    /** Minimum Ethernet header size in bytes */
    public static final int ETHERNET_HEADER_SIZE = 14;

    /** EtherType values */
    public static final int ETHERTYPE_IPV4 = 0x0800;
    public static final int ETHERTYPE_ARP  = 0x0806;
    public static final int ETHERTYPE_IPV6 = 0x86DD;
    public static final int ETHERTYPE_VLAN = 0x8100;

    /**
     * Parses the Ethernet header from raw packet data and populates the PacketInfo.
     *
     * @param rawData the complete raw packet bytes
     * @param packetInfo the PacketInfo object to populate
     * @return the offset where the Ethernet payload begins, or -1 on failure
     */
    public int parse(byte[] rawData, PacketInfo packetInfo) {
        if (rawData == null || rawData.length < ETHERNET_HEADER_SIZE) {
            logger.warn("Packet too short for Ethernet header: {} bytes",
                    rawData != null ? rawData.length : 0);
            return -1;
        }

        try {
            // Destination MAC (bytes 0-5)
            String dstMac = ByteUtils.toMacAddress(rawData, 0);
            packetInfo.setDstMac(dstMac);

            // Source MAC (bytes 6-11)
            String srcMac = ByteUtils.toMacAddress(rawData, 6);
            packetInfo.setSrcMac(srcMac);

            // EtherType (bytes 12-13)
            int etherType = ByteUtils.readUint16(rawData, 12);

            int payloadOffset = ETHERNET_HEADER_SIZE;

            // Handle 802.1Q VLAN tagging
            if (etherType == ETHERTYPE_VLAN) {
                if (rawData.length < ETHERNET_HEADER_SIZE + 4) {
                    logger.warn("Packet too short for VLAN header");
                    return -1;
                }
                // Skip VLAN tag (4 bytes: 2 TCI + 2 inner EtherType)
                etherType = ByteUtils.readUint16(rawData, 16);
                payloadOffset = ETHERNET_HEADER_SIZE + 4;
            }

            packetInfo.setEtherType(etherType);

            logger.debug("Ethernet: {} -> {} | EtherType: 0x{}", srcMac, dstMac,
                    String.format("%04x", etherType));

            return payloadOffset;

        } catch (Exception e) {
            logger.error("Error parsing Ethernet header: {}", e.getMessage());
            return -1;
        }
    }

    /**
     * Checks if the EtherType indicates an IPv4 payload.
     */
    public static boolean isIpv4(int etherType) {
        return etherType == ETHERTYPE_IPV4;
    }

    /**
     * Checks if the EtherType indicates an IPv6 payload.
     */
    public static boolean isIpv6(int etherType) {
        return etherType == ETHERTYPE_IPV6;
    }
}
