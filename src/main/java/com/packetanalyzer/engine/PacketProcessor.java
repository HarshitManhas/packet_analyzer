package com.packetanalyzer.engine;

import com.packetanalyzer.model.AppType;
import com.packetanalyzer.model.PacketInfo;
import com.packetanalyzer.parser.*;
import com.packetanalyzer.utils.PacketUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Processes a single raw packet through the protocol parsing pipeline:
 * Ethernet → IP → TCP/UDP → TLS/HTTP DPI → Application classification.
 *
 * Matches the C++ packet_parser.cpp + sni_extractor.cpp functionality.
 */
public class PacketProcessor {
    private static final Logger logger = LoggerFactory.getLogger(PacketProcessor.class);

    private final EthernetParser ethernetParser = new EthernetParser();
    private final IPParser ipParser = new IPParser();
    private final TCPParser tcpParser = new TCPParser();
    private final UDPParser udpParser = new UDPParser();
    private final TLSParser tlsParser = new TLSParser();
    private final HTTPParser httpParser = new HTTPParser();

    /**
     * Processes a raw packet through all protocol layers.
     * @return true if the packet was successfully parsed
     */
    public boolean process(PacketInfo packet) {
        byte[] rawData = packet.getRawData();
        if (rawData == null || rawData.length == 0) {
            logger.warn("Empty packet data");
            return false;
        }

        // Layer 2: Ethernet
        int ipOffset = ethernetParser.parse(rawData, packet);
        if (ipOffset < 0) {
            logger.debug("Failed to parse Ethernet header");
            return false;
        }

        // Only process IPv4
        if (!EthernetParser.isIpv4(packet.getEtherType())) {
            logger.debug("Non-IPv4 packet (EtherType: 0x{})", String.format("%04x", packet.getEtherType()));
            return false;
        }

        // Layer 3: IP
        int transportOffset = ipParser.parse(rawData, ipOffset, packet);
        if (transportOffset < 0) {
            logger.debug("Failed to parse IP header");
            return false;
        }

        // Layer 4: TCP or UDP
        if (packet.isTcp()) {
            int payloadOffset = tcpParser.parse(rawData, transportOffset, packet);
            if (payloadOffset < 0) {
                logger.debug("Failed to parse TCP header");
                return false;
            }
        } else if (packet.isUdp()) {
            int payloadOffset = udpParser.parse(rawData, transportOffset, packet);
            if (payloadOffset < 0) {
                logger.debug("Failed to parse UDP header");
                return false;
            }
        }

        // DPI: TLS SNI extraction (for HTTPS on port 443)
        if (packet.hasPayload() && (packet.getDstPort() == 443 || packet.getSrcPort() == 443)) {
            tlsParser.parse(packet);
        }

        // DPI: HTTP Host header extraction (for HTTP on port 80)
        if (packet.hasPayload() && packet.getDetectedDomain() == null
                && (packet.getDstPort() == 80 || packet.getSrcPort() == 80)) {
            httpParser.parse(packet);
        }

        // Application classification
        classifyApplication(packet);

        return true;
    }

    /**
     * Classifies the application type based on detected domain, port, and payload signatures.
     */
    private void classifyApplication(PacketInfo packet) {
        // First try domain-based classification
        if (packet.getDetectedDomain() != null) {
            String domain = packet.getDetectedDomain().toLowerCase();
            if (domain.contains("youtube") || domain.contains("googlevideo")) {
                packet.setAppType(AppType.YOUTUBE);
            } else if (domain.contains("google")) {
                packet.setAppType(AppType.GOOGLE);
            } else if (domain.contains("github")) {
                packet.setAppType(AppType.GITHUB);
            } else if (domain.contains("facebook") || domain.contains("fbcdn")) {
                packet.setAppType(AppType.FACEBOOK);
            } else if (domain.contains("twitter") || domain.contains("twimg")) {
                packet.setAppType(AppType.TWITTER);
            } else if (domain.contains("netflix") || domain.contains("nflx")) {
                packet.setAppType(AppType.NETFLIX);
            } else if (domain.contains("amazon") || domain.contains("aws")) {
                packet.setAppType(AppType.AMAZON);
            } else if (domain.contains("microsoft") || domain.contains("azure") || domain.contains("msn")) {
                packet.setAppType(AppType.MICROSOFT);
            } else if (packet.getTlsVersion() != null) {
                packet.setAppType(AppType.TLS);
            }
            return;
        }

        // Fall back to port-based classification
        if (packet.getAppType() == AppType.UNKNOWN) {
            packet.setAppType(PacketUtils.classifyByPort(packet.getSrcPort(), packet.getDstPort()));
        }

        // TLS detection by port
        if (packet.getAppType() == AppType.HTTPS && packet.getTlsVersion() != null) {
            packet.setAppType(AppType.TLS);
        }
    }
}
