package com.packetanalyzer.parser;

import com.packetanalyzer.model.PacketInfo;
import org.pcap4j.core.PcapHandle;
import org.pcap4j.core.Pcaps;
import org.pcap4j.packet.Packet;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.time.Instant;
import java.util.ArrayList;
import java.util.List;
import java.util.function.Consumer;

/**
 * Reads PCAP files using the pcap4j library and converts raw packets
 * into PacketInfo objects for further processing.
 */
public class PcapReader {
    private static final Logger logger = LoggerFactory.getLogger(PcapReader.class);

    /**
     * Reads all packets from a PCAP file and returns them as PacketInfo objects.
     */
    public List<PacketInfo> readAll(String filePath) {
        List<PacketInfo> packets = new ArrayList<>();
        read(filePath, packets::add);
        return packets;
    }

    /**
     * Reads packets from a PCAP file, passing each to the consumer as it's read.
     * More memory-efficient for large files.
     */
    public void read(String filePath, Consumer<PacketInfo> consumer) {
        logger.info("Opening PCAP file: {}", filePath);

        try (PcapHandle handle = Pcaps.openOffline(filePath)) {
            int count = 0;
            Packet packet;

            while ((packet = handle.getNextPacket()) != null) {
                try {
                    byte[] rawData = packet.getRawData();
                    PacketInfo packetInfo = new PacketInfo();
                    packetInfo.setRawData(rawData);
                    packetInfo.setLength(rawData.length);
                    packetInfo.setTimestamp(
                        handle.getTimestamp() != null
                            ? handle.getTimestamp().toInstant()
                            : Instant.now()
                    );

                    consumer.accept(packetInfo);
                    count++;
                } catch (Exception e) {
                    logger.warn("Error reading packet #{}: {}", count + 1, e.getMessage());
                }
            }

            logger.info("Read {} packets from {}", count, filePath);

        } catch (Exception e) {
            logger.error("Failed to open PCAP file '{}': {}", filePath, e.getMessage());
            throw new RuntimeException("Failed to read PCAP file: " + filePath, e);
        }
    }
}
