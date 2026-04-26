package com.packetanalyzer.engine;

import com.packetanalyzer.model.AppType;
import com.packetanalyzer.model.PacketInfo;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.ArrayList;
import java.util.List;
import java.util.function.Predicate;

/**
 * Manages filtering and blocking rules applied to packets.
 * Rules can block packets based on IP addresses, ports, domains,
 * application types, or custom predicates.
 *
 * Matches the C++ rule_manager.h functionality:
 * - IP blacklist
 * - App blacklist (by AppType)
 * - Domain blacklist (substring match on SNI/Host)
 * - Port blacklist
 * - Custom predicate rules
 */
public class RuleManager {
    private static final Logger logger = LoggerFactory.getLogger(RuleManager.class);

    private final List<String> blockedIps = new ArrayList<>();
    private final List<String> blockedDomains = new ArrayList<>();
    private final List<Integer> blockedPorts = new ArrayList<>();
    private final List<AppType> blockedApps = new ArrayList<>();
    private final List<Predicate<PacketInfo>> customRules = new ArrayList<>();

    /**
     * Adds an IP address to the block list.
     */
    public void blockIp(String ip) {
        blockedIps.add(ip);
        logger.info("[Rules] Blocked IP: {}", ip);
    }

    /**
     * Adds a domain to the block list (substring match).
     */
    public void blockDomain(String domain) {
        blockedDomains.add(domain.toLowerCase());
        logger.info("[Rules] Blocked domain: {}", domain);
    }

    /**
     * Adds a port to the block list.
     */
    public void blockPort(int port) {
        blockedPorts.add(port);
        logger.info("[Rules] Blocked port: {}", port);
    }

    /**
     * Adds an application type to the block list.
     * Matches C++ --block-app functionality.
     */
    public void blockApp(AppType appType) {
        blockedApps.add(appType);
        logger.info("[Rules] Blocked app: {}", appType.getName());
    }

    /**
     * Adds an application type to the block list by name string.
     * Convenience method for CLI argument parsing.
     */
    public void blockApp(String appName) {
        for (AppType type : AppType.values()) {
            if (type.getName().equalsIgnoreCase(appName) || type.name().equalsIgnoreCase(appName)) {
                blockApp(type);
                return;
            }
        }
        logger.warn("[Rules] Unknown app type: {}", appName);
    }

    /**
     * Adds a custom rule predicate. If the predicate returns true, the packet is blocked.
     */
    public void addCustomRule(Predicate<PacketInfo> rule) {
        customRules.add(rule);
    }

    /**
     * Evaluates all rules against a packet. Sets blocked flag and reason if any rule matches.
     * Checks in order: IP → App → Port → Domain → Custom rules.
     * @return true if the packet should be blocked
     */
    public boolean evaluate(PacketInfo packet) {
        // Check blocked IPs (source)
        if (packet.getSrcIp() != null && blockedIps.contains(packet.getSrcIp())) {
            packet.setBlocked(true);
            packet.setBlockReason("Blocked source IP: " + packet.getSrcIp());
            return true;
        }
        // Check blocked IPs (destination)
        if (packet.getDstIp() != null && blockedIps.contains(packet.getDstIp())) {
            packet.setBlocked(true);
            packet.setBlockReason("Blocked destination IP: " + packet.getDstIp());
            return true;
        }

        // Check blocked app types
        if (packet.getAppType() != null && blockedApps.contains(packet.getAppType())) {
            packet.setBlocked(true);
            packet.setBlockReason("Blocked app: " + packet.getAppType().getName());
            return true;
        }

        // Check blocked ports
        if (blockedPorts.contains(packet.getSrcPort()) || blockedPorts.contains(packet.getDstPort())) {
            packet.setBlocked(true);
            packet.setBlockReason("Blocked port: " + packet.getSrcPort() + "/" + packet.getDstPort());
            return true;
        }

        // Check blocked domains (substring match, like C++ version)
        if (packet.getDetectedDomain() != null) {
            String domain = packet.getDetectedDomain().toLowerCase();
            for (String blocked : blockedDomains) {
                if (domain.contains(blocked)) {
                    packet.setBlocked(true);
                    packet.setBlockReason("Blocked domain: " + domain);
                    return true;
                }
            }
        }

        // Check custom rules
        for (Predicate<PacketInfo> rule : customRules) {
            if (rule.test(packet)) {
                packet.setBlocked(true);
                if (packet.getBlockReason() == null) {
                    packet.setBlockReason("Custom rule match");
                }
                return true;
            }
        }

        return false;
    }

    /**
     * Loads some default example rules for demonstration.
     */
    public void loadDefaultRules() {
        // Example: block known ad domains
        blockDomain("ads.example.com");
        blockDomain("tracker.example.com");
        logger.info("Loaded default blocking rules");
    }

    public List<String> getBlockedIps() { return blockedIps; }
    public List<String> getBlockedDomains() { return blockedDomains; }
    public List<Integer> getBlockedPorts() { return blockedPorts; }
    public List<AppType> getBlockedApps() { return blockedApps; }
}
