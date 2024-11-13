#pragma once

#include "include.h"        // Include the necessary headers
#include "argumentParser.h" // Adjust paths as needed
#include "pcap.h"           // for PCAPParser
#include "udp.h"            // for udpConnection

class DNSMonitor
{
public:
    DNSMonitor(int argc, char *argv[]); // Constructor accepting command-line arguments
    int run();                          // Main method to run the DNS monitoring logic

private:
    bool handlePCAPFile();      // Method to handle PCAP file parsing
    bool handleUDPConnection(); // Method to handle UDP connection

    argumentParser parser; // Argument parser
    inputArguments args;   // Parsed arguments
};