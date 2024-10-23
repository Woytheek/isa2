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

void getCurrentDateTime(char *buffer, size_t bufferSize);
void parseDNSMessage(char *buffer, ssize_t size, bool verbose, const char *srcIP, const char *dstIP);
void printSimplifiedDNS(DNSHeader *dnsHeader, const char *srcIP, const char *dstIP);
void printVerboseDNS(DNSHeader *dnsHeader, const char *srcIP, const char *dstIP, ssize_t size, char *buffer);
char *decodeDomainName(const char *buffer, char *output, size_t outputSize);
