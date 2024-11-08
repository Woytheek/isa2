#pragma once

#include "include.h"
#include "argumentParser.h"

// DNS header structure
struct DNSHeader
{
    uint16_t id;      // Transaction ID
    uint16_t flags;   // Flags and response codes
    uint16_t qdCount; // Number of questions
    uint16_t anCount; // Number of answers
    uint16_t nsCount; // Number of authority records
    uint16_t arCount; // Number of additional records
};

void printBytes(const unsigned char *data, int size);
void parseRawPacket(unsigned char *buffer, ssize_t bufferSize, struct pcap_pkthdr header, inputArguments args);
void parseDNSMessage(unsigned char *packet, ssize_t size, char *dateTime, bool v);
void printVerboseDNS(DNSHeader *dnsHeader, const char *srcIP, const char *dstIP, ssize_t size, unsigned char *buffer, char *dateTime);
void printSimplifiedDNS(DNSHeader *dnsHeader, const char *srcIP, const char *dstIP, char *dateTime);
int isDNSPacket(const u_char *packet, int length);
