#include "../include/app.h"

DNSMonitor::DNSMonitor(int argc, char *argv[])
{
    parser.parseArguments(argc, argv, args); // Parse arguments in constructor
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
            std::cerr << "Failed to establish UDP connection!" << std::endl;
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

    std::cerr << "Error: Interface not provided!" << std::endl;
    return 1;
}