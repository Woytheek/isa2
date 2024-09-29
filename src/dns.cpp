#include "../include/dns.h"

// Function to parse and print DNS header information
void parseDNSMessage(char *buffer, ssize_t size)
{
    if (size < static_cast<ssize_t>(sizeof(DNSHeader)))
    {

        std::cerr << "Invalid DNS packet size" << std::endl;
        return;
    }

    DNSHeader *dnsHeader = (DNSHeader *)buffer;

    // Print the DNS header
    printf("Transaction ID: 0x%X\n", ntohs(dnsHeader->id));
    printf("Flags: 0x%X\n", ntohs(dnsHeader->flags));
    printf("Questions: %d\n", ntohs(dnsHeader->qdCount));
    printf("Answer RRs: %d\n", ntohs(dnsHeader->anCount));
    printf("Authority RRs: %d\n", ntohs(dnsHeader->nsCount));
    printf("Additional RRs: %d\n", ntohs(dnsHeader->arCount));

    // If questions exist, print them (for simplicity, just print the raw question data)
    if (ntohs(dnsHeader->qdCount) > 0)
    {
        printf("DNS Question Section (raw):\n");
        for (int i = sizeof(DNSHeader); i < size; ++i)
        {
            printf("%02X ", (unsigned char)buffer[i]);
        }
        printf("\n");
    }
}
