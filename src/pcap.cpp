#include "../include/pcap.h"

PCAPParser::PCAPParser(const inputArguments &args)
    : errbuf{}, handle(nullptr), args(args)
{ // Match order in header file

    // Initialize the error buffer with an empty string
    errbuf[0] = '\0';
}

bool PCAPParser::openFile()
{
    // Attempt to open the PCAP file in offline mode
    handle = pcap_open_offline(args.pcapFile.c_str(), errbuf);
    if (handle == nullptr)
    {
        fprintf(stderr, "Could not open file %s: %s\n", args.pcapFile.c_str(), errbuf);
        return false;
    }
    return true;
}

void PCAPParser::closeFile()
{
    if (handle != nullptr)
    {
        pcap_close(handle);
        handle = nullptr;
    }
}

int PCAPParser::getDNSOffset(const unsigned char *packet, int length) const
{
    // Placeholder function to check if a packet is DNS and return the offset
    return DNSParser::isDNSPacket(packet, length);
}

int PCAPParser::parseFile()
{
    // Open the file and check for success
    if (!openFile())
    {
        return 1;
    }

    struct pcap_pkthdr header;
    const unsigned char *packet;

    // Loop through packets
    while ((packet = pcap_next(handle, &header)) != nullptr)
    {
        // Check if packet is DNS and get offset
        int offset = getDNSOffset(packet, header.len);
        if (offset != -1)
        {
            // Parse the raw packet if it's a DNS packet
            //parseRawPacket((unsigned char *)packet, header.len, header, args, offset);
            DNSParser::parseRawPacket((unsigned char *)packet, header.len, header, args, offset);
        }
    }

    // Close the file after parsing
    closeFile();
    return 0;
}