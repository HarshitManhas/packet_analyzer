package com.packetanalyzer.parser;

import com.packetanalyzer.model.PacketInfo;
import com.packetanalyzer.utils.ByteUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Parses TLS records to extract SNI from ClientHello messages.
 */
public class TLSParser {
    private static final Logger logger = LoggerFactory.getLogger(TLSParser.class);
    private static final int CONTENT_TYPE_HANDSHAKE = 0x16;
    private static final int HANDSHAKE_CLIENT_HELLO = 0x01;
    private static final int EXTENSION_SNI = 0x0000;
    private static final int SNI_HOST_NAME = 0x00;

    public boolean parse(PacketInfo packetInfo) {
        byte[] payload = packetInfo.getPayload();
        if (payload == null || payload.length < 6) return false;

        try {
            int contentType = ByteUtils.readUint8(payload, 0);
            if (contentType != CONTENT_TYPE_HANDSHAKE) return false;

            int major = ByteUtils.readUint8(payload, 1);
            int minor = ByteUtils.readUint8(payload, 2);
            packetInfo.setTlsVersion(getTlsVersion(major, minor));

            if (payload.length < 6) return false;
            int handshakeType = ByteUtils.readUint8(payload, 5);
            if (handshakeType != HANDSHAKE_CLIENT_HELLO) return true;

            return parseClientHello(payload, 5, packetInfo);
        } catch (Exception e) {
            logger.debug("Error parsing TLS: {}", e.getMessage());
            return false;
        }
    }

    private boolean parseClientHello(byte[] p, int offset, PacketInfo info) {
        try {
            int pos = offset + 4 + 2 + 32; // skip type(1)+len(3)+version(2)+random(32)
            if (pos >= p.length) return false;

            int sessionIdLen = ByteUtils.readUint8(p, pos);
            pos += 1 + sessionIdLen;
            if (pos + 2 > p.length) return false;

            int cipherLen = ByteUtils.readUint16(p, pos);
            pos += 2 + cipherLen;
            if (pos >= p.length) return false;

            int compLen = ByteUtils.readUint8(p, pos);
            pos += 1 + compLen;
            if (pos + 2 > p.length) return false;

            int extLen = ByteUtils.readUint16(p, pos);
            pos += 2;
            int extEnd = pos + extLen;

            while (pos + 4 <= extEnd && pos + 4 <= p.length) {
                int extType = ByteUtils.readUint16(p, pos);
                int extLength = ByteUtils.readUint16(p, pos + 2);
                pos += 4;
                if (extType == EXTENSION_SNI) return parseSni(p, pos, extLength, info);
                pos += extLength;
            }
        } catch (Exception e) {
            logger.debug("Error parsing ClientHello: {}", e.getMessage());
        }
        return false;
    }

    private boolean parseSni(byte[] p, int offset, int length, PacketInfo info) {
        try {
            int pos = offset + 2;
            while (pos + 3 <= offset + length && pos + 3 <= p.length) {
                int nameType = ByteUtils.readUint8(p, pos);
                int nameLen = ByteUtils.readUint16(p, pos + 1);
                pos += 3;
                if (nameType == SNI_HOST_NAME && pos + nameLen <= p.length) {
                    String name = new String(p, pos, nameLen, java.nio.charset.StandardCharsets.US_ASCII);
                    info.setDetectedDomain(name);
                    logger.info("TLS SNI detected: {}", name);
                    return true;
                }
                pos += nameLen;
            }
        } catch (Exception e) {
            logger.debug("Error parsing SNI: {}", e.getMessage());
        }
        return false;
    }

    private String getTlsVersion(int major, int minor) {
        if (major == 3) {
            return switch (minor) {
                case 0 -> "SSLv3";
                case 1 -> "TLSv1.0";
                case 2 -> "TLSv1.1";
                case 3 -> "TLSv1.2";
                case 4 -> "TLSv1.3";
                default -> "TLS " + major + "." + minor;
            };
        }
        return "TLS " + major + "." + minor;
    }
}
