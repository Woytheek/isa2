#pragma once
#include "include.h"
#include "dns.h"
#include "argumentParser.h"

class PCAPParser
{
public:
    // Constructor that takes input arguments for the PCAP file
    explicit PCAPParser(const inputArguments &args);

    // Method to parse the PCAP file
    int parseFile();

private:
    // Error buffer and PCAP handle
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t *handle;

    // Arguments containing file path and parsing options
    inputArguments args;
    // Helper method to open the PCAP file
    bool openFile();

    // Helper method to close the PCAP file
    void closeFile();

    // Checks if a packet is a DNS packet and returns the offset if true
    int getDNSOffset(const unsigned char *packet, int length) const;
};