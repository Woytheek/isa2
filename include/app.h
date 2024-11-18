/**
 * @file app.h
 * @author Vojtěch Kuchař xkucha30
 * @brief Defines the DNSMonitor class for managing DNS monitoring tasks, including
 *        handling command-line arguments, processing PCAP files, and establishing
 *        UDP connections for real-time DNS monitoring.
 * @version 1.0
 * @date 2024-11-17
 *
 * @copyright Copyright (c) 2024
 *
 */

#pragma once

#include "include.h"        // Include the necessary headers
#include "argumentParser.h" // Adjust paths as needed
#include "pcap.h"           // for PCAPParser
#include "udp.h"            // for udpConnection

class DNSMonitor
{
public:
    /**
     * @brief Constructs the DNSMonitor object and parses input arguments.
     *        This constructor initializes the argument parser and stores the parsed
     *        arguments into the provided `args` structure.
     *
     * @param argc The number of command-line arguments.
     * @param argv The array of command-line arguments.
     */
    DNSMonitor(int argc, char *argv[]);

    /**
     * @brief Runs the DNS monitoring logic based on the parsed input arguments.
     *        This method decides whether to handle a PCAP file or establish a UDP
     *        connection for real-time monitoring, and returns an error code if
     *        any operation fails.
     *
     * @return 0 if successful, 1 otherwise.
     */
    int run();

private:
    /**
     * @brief Handles the parsing of the specified PCAP file.
     *        This method initializes the `PCAPParser` with the parsed arguments
     *        and attempts to parse the PCAP file. It returns true if parsing succeeds.
     *
     * @return `true` if PCAP parsing is successful, otherwise `false`.
     */
    bool handlePCAPFile();

    /**
     * @brief Establishes a UDP connection based on the parsed arguments.
     *        This method attempts to start the UDP connection if an interface is
     *        provided. If the interface is missing, it prints an error message.
     *
     * @return `true` if the UDP connection is successfully established, otherwise `false`.
     */
    bool handleUDPConnection();

    argumentParser parser; // Argument parser
    inputArguments args;   // Parsed arguments
};