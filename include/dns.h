#pragma once

#include "include.h"

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

void printBytes(char *data, int size);
void printSimplifiedDNS(DNSHeader *dnsHeader, const char *srcIP, const char *dstIP, struct pcap_pkthdr *header);
void printVerboseDNS(DNSHeader *dnsHeader, const char *srcIP, const char *dstIP, ssize_t size, char *buffer, struct pcap_pkthdr *header);
void parseDNSMessage(char *packet, ssize_t size, struct pcap_pkthdr header, bool verbose);
