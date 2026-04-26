package com.packetanalyzer;

import com.packetanalyzer.engine.DPIEngine;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Application entry point for the Packet Analyzer.
 * Reads a PCAP file and runs it through the DPI Engine.
 *
 * Matches the C++ command-line interface:
 *
 * Usage:
 *   java -jar packet-analyzer.jar <input.pcap> [output.pcap] [options]
 *
 * Options:
 *   --block-app <AppName>      Block traffic by application type (e.g., YouTube, Facebook)
 *   --block-ip <IP>            Block traffic from/to IP address
 *   --block-domain <domain>    Block traffic matching domain (substring match)
 *   --block-port <port>        Block traffic on port number
 *
 * Examples:
 *   java -jar packet-analyzer.jar input/sample.pcap
 *   java -jar packet-analyzer.jar input/sample.pcap output/filtered.pcap
 *   java -jar packet-analyzer.jar input/sample.pcap output/filtered.pcap --block-app YouTube --block-ip 192.168.1.50
 */
public class Main {

    private static final Logger logger = LoggerFactory.getLogger(Main.class);
    private static final String DEFAULT_PCAP = "input/sample.pcap";

    public static void main(String[] args) {
        if (args.length > 0 && ("--help".equals(args[0]) || "-h".equals(args[0]))) {
            printUsage();
            return;
        }

        String inputFile = (args.length > 0 && !args[0].startsWith("--")) ? args[0] : DEFAULT_PCAP;

        logger.info("Packet Analyzer v1.0");
        logger.info("Input file: {}", inputFile);

        // Verify input file exists
        java.io.File file = new java.io.File(inputFile);
        if (!file.exists()) {
            logger.error("PCAP file not found: {}", inputFile);
            System.err.println("Error: PCAP file not found: " + inputFile);
            printUsage();
            System.exit(1);
        }

        DPIEngine engine = new DPIEngine();
        int numLBs = 2;
        int fpsPerLB = 2;

        // Parse remaining arguments
        String outputFile = null;
        int i = 1;

        // Check if second arg is an output file (not a flag)
        if (args.length > 1 && !args[1].startsWith("--")) {
            outputFile = args[1];
            i = 2;
        }

        // Parse CLI flags (matching C++ --block-app, --block-ip, --block-domain, --lbs, --fps)
        while (i < args.length) {
            String flag = args[i];
            switch (flag) {
                case "--block-app":
                    if (i + 1 < args.length) {
                        engine.getRuleManager().blockApp(args[++i]);
                    } else {
                        System.err.println("Error: --block-app requires an argument");
                        System.exit(1);
                    }
                    break;
                case "--block-ip":
                    if (i + 1 < args.length) {
                        engine.getRuleManager().blockIp(args[++i]);
                    } else {
                        System.err.println("Error: --block-ip requires an argument");
                        System.exit(1);
                    }
                    break;
                case "--block-domain":
                    if (i + 1 < args.length) {
                        engine.getRuleManager().blockDomain(args[++i]);
                    } else {
                        System.err.println("Error: --block-domain requires an argument");
                        System.exit(1);
                    }
                    break;
                case "--block-port":
                    if (i + 1 < args.length) {
                        try {
                            engine.getRuleManager().blockPort(Integer.parseInt(args[++i]));
                        } catch (NumberFormatException e) {
                            System.err.println("Error: --block-port requires a valid port number");
                            System.exit(1);
                        }
                    } else {
                        System.err.println("Error: --block-port requires an argument");
                        System.exit(1);
                    }
                    break;
                case "--lbs":
                    if (i + 1 < args.length) {
                        numLBs = Integer.parseInt(args[++i]);
                    } else {
                        System.err.println("Error: --lbs requires a number");
                        System.exit(1);
                    }
                    break;
                case "--fps":
                    if (i + 1 < args.length) {
                        fpsPerLB = Integer.parseInt(args[++i]);
                    } else {
                        System.err.println("Error: --fps requires a number");
                        System.exit(1);
                    }
                    break;
                default:
                    System.err.println("Unknown option: " + flag);
                    printUsage();
                    System.exit(1);
            }
            i++;
        }

        // Configure thread architecture
        engine.setThreadConfig(numLBs, fpsPerLB);

        // Set output file if provided
        if (outputFile != null) {
            engine.setOutputPath(outputFile);
            logger.info("Output file: {}", outputFile);
        }

        engine.processFile(inputFile);
    }

    private static void printUsage() {
        System.out.println();
        System.out.println("╔══════════════════════════════════════════════════════════════╗");
        System.out.println("║              PACKET ANALYZER - DPI Engine v1.0               ║");
        System.out.println("╠══════════════════════════════════════════════════════════════╣");
        System.out.println("║                                                              ║");
        System.out.println("║  Usage:                                                      ║");
        System.out.println("║    java -jar packet-analyzer.jar <input> [output] [options]  ║");
        System.out.println("║                                                              ║");
        System.out.println("║  Options:                                                    ║");
        System.out.println("║    --block-app <name>     Block by app (YouTube, Facebook)   ║");
        System.out.println("║    --block-ip <ip>        Block by IP address                ║");
        System.out.println("║    --block-domain <name>  Block by domain (substring match)  ║");
        System.out.println("║    --block-port <port>    Block by port number                ║");
        System.out.println("║    --lbs <N>              Number of Load Balancer threads     ║");
        System.out.println("║    --fps <N>              Number of Fast Paths per LB         ║");
        System.out.println("║    --help, -h             Show this help message              ║");
        System.out.println("║                                                              ║");
        System.out.println("║  Examples:                                                   ║");
        System.out.println("║    java -jar packet-analyzer.jar capture.pcap                ║");
        System.out.println("║    java -jar packet-analyzer.jar in.pcap out.pcap            ║");
        System.out.println("║    java -jar packet-analyzer.jar in.pcap out.pcap \\          ║");
        System.out.println("║        --block-app YouTube --block-domain facebook           ║");
        System.out.println("║                                                              ║");
        System.out.println("╚══════════════════════════════════════════════════════════════╝");
        System.out.println();
    }
}
