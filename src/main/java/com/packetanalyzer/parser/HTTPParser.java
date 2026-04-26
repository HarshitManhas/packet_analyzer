package com.packetanalyzer.parser;

import com.packetanalyzer.model.PacketInfo;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.nio.charset.StandardCharsets;

/**
 * Parses HTTP/1.x request headers to extract the Host header value.
 * This enables domain detection for plain HTTP traffic (port 80).
 *
 * HTTP Request Format:
 *   GET /path HTTP/1.1\r\n
 *   Host: www.example.com\r\n
 *   ...other headers...\r\n
 *   \r\n
 */
public class HTTPParser {
    private static final Logger logger = LoggerFactory.getLogger(HTTPParser.class);

    private static final String[] HTTP_METHODS = {
        "GET ", "POST ", "PUT ", "DELETE ", "HEAD ", "OPTIONS ", "PATCH ", "CONNECT "
    };
    private static final String HOST_HEADER = "host:";

    /**
     * Attempts to extract the Host header from an HTTP request payload.
     *
     * @param packetInfo the PacketInfo with payload already set
     * @return true if an HTTP Host header was found and extracted
     */
    public boolean parse(PacketInfo packetInfo) {
        byte[] payload = packetInfo.getPayload();
        if (payload == null || payload.length < 16) {
            return false;
        }

        try {
            // Convert enough of the payload to check for HTTP methods
            // Limit to first 2048 bytes to avoid processing huge payloads
            int checkLen = Math.min(payload.length, 2048);
            String header = new String(payload, 0, checkLen, StandardCharsets.US_ASCII);

            // Verify this is an HTTP request by checking for a known method
            boolean isHttp = false;
            for (String method : HTTP_METHODS) {
                if (header.startsWith(method)) {
                    isHttp = true;
                    break;
                }
            }

            if (!isHttp) {
                return false;
            }

            // Search for the Host header (case-insensitive)
            String headerLower = header.toLowerCase();
            int hostIdx = headerLower.indexOf(HOST_HEADER);
            if (hostIdx < 0) {
                return false;
            }

            // Extract the Host value: skip "Host: " and read until \r\n
            int valueStart = hostIdx + HOST_HEADER.length();
            // Skip any leading whitespace
            while (valueStart < header.length() && header.charAt(valueStart) == ' ') {
                valueStart++;
            }

            int valueEnd = header.indexOf('\r', valueStart);
            if (valueEnd < 0) {
                valueEnd = header.indexOf('\n', valueStart);
            }
            if (valueEnd < 0) {
                valueEnd = header.length();
            }

            String host = header.substring(valueStart, valueEnd).trim();

            // Remove port if present (e.g., "example.com:8080" -> "example.com")
            int colonIdx = host.indexOf(':');
            if (colonIdx > 0) {
                host = host.substring(0, colonIdx);
            }

            if (!host.isEmpty()) {
                packetInfo.setDetectedDomain(host);
                logger.info("HTTP Host detected: {}", host);
                return true;
            }

        } catch (Exception e) {
            logger.debug("Error parsing HTTP header: {}", e.getMessage());
        }

        return false;
    }
}
