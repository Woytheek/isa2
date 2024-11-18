/**
 * @file pcap.cpp
 * @author Vojtěch Kuchař xkucha30
 * @brief Implements functionality for opening and parsing PCAP files.
 *        Includes methods for extracting DNS packets and managing PCAP file operations.
 * @version 1.0
 * @date 2024-11-17
 *
 * @copyright Copyright (c) 2024
 *
 */

#include "../include/pcap.h"

PCAPParser::PCAPParser(const inputArguments &args)
    : errbuf{}, handle(nullptr), args(args)
{
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

    return DNSParser::isDNSPacket(packet, length);
}

int PCAPParser::parseFile()
{
    struct pcap_pkthdr header;
    const unsigned char *packet;

    if (!openFile())
    {
        return 1;
    }

    // Loop through packets
    while ((packet = pcap_next(handle, &header)) != nullptr)
    {
        DNSParser parser(args);
        int offset = getDNSOffset(packet, header.len);
        if (offset != -1)
        {
            parser.parseRawPacket((unsigned char *)packet, header.len, header, offset);
        }
    }

    closeFile();
    return 0;
}