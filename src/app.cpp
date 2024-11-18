/**
 * @file app.cpp
 * @author Vojtěch Kuchař xkucha30
 * @brief Implements the DNSMonitor class, providing the logic for DNS monitoring tasks.
 *        This includes parsing input arguments, handling PCAP file parsing, and
 *        establishing UDP connections for real-time monitoring.
 * @version 1.0
 * @date 2024-11-17
 *
 * @copyright Copyright (c) 2024
 *
 */

#include "../include/app.h"

DNSMonitor::DNSMonitor(int argc, char *argv[])
{
    parser.parseArguments(argc, argv, args);
}

int DNSMonitor::run()
{
    if (args.p)
    {
        // Handle PCAP file if specified
        if (!handlePCAPFile())
        {
            std::cerr << "Error while parsing the PCAP file." << std::endl;
            return 1;
        }
    }
    else
    {
        // Handle UDP connection if no PCAP file is provided
        if (!handleUDPConnection())
        {
            std::cerr << "Error while establishing the UDP connection." << std::endl;
            return 1;
        }
    }
    return 0;
}

bool DNSMonitor::handlePCAPFile()
{
    PCAPParser pcapParser(args);
    return pcapParser.parseFile() == 0; // Return true if parsing succeeds
}

bool DNSMonitor::handleUDPConnection()
{
    if (!args.interface.empty())
    {
        UDPConnection udpConnection(args);
        return udpConnection.start(); // Start the UDP connection
    }
    std::cerr << "No interface provided for UDP connection." << std::endl;
    return 1;
}