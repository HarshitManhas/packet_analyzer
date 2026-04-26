package com.packetanalyzer.model;

/**
 * Enumeration of application types detected via Deep Packet Inspection.
 * Used for traffic classification based on packet signatures, port numbers,
 * and TLS SNI inspection.
 */
public enum AppType {
    HTTP("HTTP", "Web Traffic"),
    HTTPS("HTTPS", "Secure Web Traffic"),
    DNS("DNS", "Domain Name System"),
    TLS("TLS", "Transport Layer Security"),
    SSH("SSH", "Secure Shell"),
    FTP("FTP", "File Transfer Protocol"),
    SMTP("SMTP", "Simple Mail Transfer Protocol"),
    IMAP("IMAP", "Internet Message Access Protocol"),
    POP3("POP3", "Post Office Protocol"),
    DHCP("DHCP", "Dynamic Host Configuration Protocol"),
    NTP("NTP", "Network Time Protocol"),
    YOUTUBE("YouTube", "YouTube Video Streaming"),
    GOOGLE("Google", "Google Services"),
    GITHUB("GitHub", "GitHub Services"),
    FACEBOOK("Facebook", "Facebook Services"),
    TWITTER("Twitter", "Twitter Services"),
    NETFLIX("Netflix", "Netflix Streaming"),
    AMAZON("Amazon", "Amazon Services"),
    MICROSOFT("Microsoft", "Microsoft Services"),
    UNKNOWN("Unknown", "Unclassified Traffic");

    private final String name;
    private final String description;

    AppType(String name, String description) {
        this.name = name;
        this.description = description;
    }

    public String getName() {
        return name;
    }

    public String getDescription() {
        return description;
    }

    @Override
    public String toString() {
        return name + " (" + description + ")";
    }
}
