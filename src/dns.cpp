#include "../include/dns.h"

#include <iostream>
#include <cstring>
#include <ctime>
#include <arpa/inet.h>

// Function to get current date and time in the required format
void getCurrentDateTime(char *buffer, size_t bufferSize)
{
    time_t now = time(0);
    struct tm tstruct;
    tstruct = *localtime(&now);
    strftime(buffer, bufferSize, "%Y-%m-%d %H:%M:%S", &tstruct);
}

// Function to parse and print DNS header information
void parseDNSMessage(char *buffer, ssize_t size, bool verbose, const char *srcIP, const char *dstIP)
{
    if (size < static_cast<ssize_t>(sizeof(DNSHeader)))
    {
        printf("Invalid DNS packet size\n");
        return;
    }

    DNSHeader *dnsHeader = (DNSHeader *)buffer;

    // Prepare values for the simplified output
    char dateTime[20];
    getCurrentDateTime(dateTime, sizeof(dateTime));
    char qr = (ntohs(dnsHeader->flags) & 0x8000) ? 'R' : 'Q'; // Query or Response
    int qdCount = ntohs(dnsHeader->qdCount);
    int anCount = ntohs(dnsHeader->anCount);
    int nsCount = ntohs(dnsHeader->nsCount);
    int arCount = ntohs(dnsHeader->arCount);

    // Simplified output
    if (!verbose)
    {
        printf("%s %s -> %s (%c %d/%d/%d/%d)\n",
               dateTime, srcIP, dstIP, qr, qdCount, anCount, nsCount, arCount);
        return;
    }

    // Verbose output (complete DNS header information)
    printf("Transaction ID: 0x%X\n", ntohs(dnsHeader->id));
    printf("Flags: 0x%X\n", ntohs(dnsHeader->flags));
    printf("Questions: %d\n", qdCount);
    printf("Answer RRs: %d\n", anCount);
    printf("Authority RRs: %d\n", nsCount);
    printf("Additional RRs: %d\n", arCount);

    // If questions exist, print them (for simplicity, just print the raw question data)
    if (qdCount > 0)
    {
        printf("DNS Question Section (raw):\n");
        for (int i = sizeof(DNSHeader); i < size; ++i)
        {
            printf("%02X ", (unsigned char)buffer[i]);
        }
        printf("\n");
    }
}
