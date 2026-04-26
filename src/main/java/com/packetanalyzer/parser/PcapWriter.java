package com.packetanalyzer.parser;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.FileOutputStream;
import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;

/**
 * Writes filtered (non-blocked) packets to a PCAP output file.
 * Implements the PCAP file format with global header and per-packet headers.
 *
 * PCAP File Format:
 *   Global Header (24 bytes) — written once
 *   [Packet Header (16 bytes) + Packet Data] — repeated per packet
 */
public class PcapWriter implements AutoCloseable {
    private static final Logger logger = LoggerFactory.getLogger(PcapWriter.class);

    // PCAP magic number (little-endian, microsecond timestamps)
    private static final int PCAP_MAGIC = 0xA1B2C3D4;
    private static final short VERSION_MAJOR = 2;
    private static final short VERSION_MINOR = 4;
    private static final int SNAPLEN = 65535;
    private static final int LINK_TYPE_ETHERNET = 1;

    private FileOutputStream outputStream;
    private int packetCount = 0;

    /**
     * Opens a PCAP file for writing and writes the global header.
     *
     * @param filePath the output file path
     * @throws IOException if the file cannot be created
     */
    public void open(String filePath) throws IOException {
        outputStream = new FileOutputStream(filePath);
        writeGlobalHeader();
        logger.info("Opened PCAP output file: {}", filePath);
    }

    /**
     * Writes the 24-byte PCAP global header.
     */
    private void writeGlobalHeader() throws IOException {
        ByteBuffer buf = ByteBuffer.allocate(24);
        buf.order(ByteOrder.LITTLE_ENDIAN);
        buf.putInt(PCAP_MAGIC);           // magic_number
        buf.putShort(VERSION_MAJOR);      // version_major
        buf.putShort(VERSION_MINOR);      // version_minor
        buf.putInt(0);                    // thiszone (GMT)
        buf.putInt(0);                    // sigfigs
        buf.putInt(SNAPLEN);              // snaplen
        buf.putInt(LINK_TYPE_ETHERNET);   // network (Ethernet)
        outputStream.write(buf.array());
    }

    /**
     * Writes a single packet (16-byte packet header + raw data).
     *
     * @param rawData   the raw packet bytes
     * @param tsSec     timestamp seconds
     * @param tsUsec    timestamp microseconds
     */
    public synchronized void writePacket(byte[] rawData, long tsSec, long tsUsec) throws IOException {
        if (outputStream == null) {
            throw new IOException("PCAP writer is not open");
        }

        int capturedLen = rawData.length;
        int originalLen = rawData.length;

        // Write 16-byte packet header
        ByteBuffer header = ByteBuffer.allocate(16);
        header.order(ByteOrder.LITTLE_ENDIAN);
        header.putInt((int) tsSec);       // ts_sec
        header.putInt((int) tsUsec);      // ts_usec
        header.putInt(capturedLen);        // incl_len
        header.putInt(originalLen);        // orig_len
        outputStream.write(header.array());

        // Write packet data
        outputStream.write(rawData);

        packetCount++;
    }

    /**
     * Writes a packet using an Instant timestamp.
     */
    public void writePacket(byte[] rawData, java.time.Instant timestamp) throws IOException {
        long epochSecond = timestamp.getEpochSecond();
        long microSecond = timestamp.getNano() / 1000;
        writePacket(rawData, epochSecond, microSecond);
    }

    /**
     * Returns the number of packets written so far.
     */
    public int getPacketCount() {
        return packetCount;
    }

    @Override
    public void close() throws IOException {
        if (outputStream != null) {
            outputStream.flush();
            outputStream.close();
            logger.info("Closed PCAP output file ({} packets written)", packetCount);
            outputStream = null;
        }
    }
}
