#include "../include/dns.h"

// Function to get current date and time in the required format
void getCurrentDateTime(char *buffer, size_t bufferSize)
{
    time_t now = time(0);
    struct tm tstruct;
    tstruct = *localtime(&now);
    strftime(buffer, bufferSize, "%Y-%m-%d %H:%M:%S", &tstruct);
}

// Funkce pro zjednodušený výpis DNS zpráv
void printSimplifiedDNS(DNSHeader *dnsHeader, const char *srcIP, const char *dstIP)
{
    char dateTime[20];
    getCurrentDateTime(dateTime, sizeof(dateTime));

    char qr = (ntohs(dnsHeader->flags) & 0x8000) ? 'R' : 'Q';
    int qdCount = ntohs(dnsHeader->qdCount);
    int anCount = ntohs(dnsHeader->anCount);
    int nsCount = ntohs(dnsHeader->nsCount);
    int arCount = ntohs(dnsHeader->arCount);

    printf("%s %s -> %s (%c %d/%d/%d/%d)\n",
           dateTime, srcIP, dstIP, qr, qdCount, anCount, nsCount, arCount);
}

// Funkce pro detailní výpis DNS zpráv
void printVerboseDNS(DNSHeader *dnsHeader, const char *srcIP, const char *dstIP, ssize_t size, char *buffer)
{
    char dateTime[20];
    getCurrentDateTime(dateTime, sizeof(dateTime));

    printf("Timestamp: %s\n", dateTime);
    printf("SrcIP: %s\n", srcIP);
    printf("DstIP: %s\n", dstIP);
    printf("SrcPort: UDP/53\n"); // Statický port DNS serveru
    printf("DstPort: UDP\n");    // Port klienta by měl být dynamický

    printf("Identifier: 0x%X\n", ntohs(dnsHeader->id));
    printf("Flags: QR=%d, OPCODE=%d, AA=%d, TC=%d, RD=%d, RA=%d, AD=%d, CD=%d, RCODE=%d\n",
           (ntohs(dnsHeader->flags) & 0x8000) >> 15, // QR
           (ntohs(dnsHeader->flags) & 0x7800) >> 11, // OPCODE
           (ntohs(dnsHeader->flags) & 0x0400) >> 10, // AA
           (ntohs(dnsHeader->flags) & 0x0200) >> 9,  // TC
           (ntohs(dnsHeader->flags) & 0x0100) >> 8,  // RD
           (ntohs(dnsHeader->flags) & 0x0080) >> 7,  // RA
           (ntohs(dnsHeader->flags) & 0x0020) >> 5,  // AD
           (ntohs(dnsHeader->flags) & 0x0010) >> 4,  // CD
           (ntohs(dnsHeader->flags) & 0x000F));      // RCODE

    // Výpis sekce "Question"
    printf("\n[Question Section]\n");
    if (ntohs(dnsHeader->qdCount) > 0)
    {
        for (int i = sizeof(DNSHeader); i < size; ++i)
        {
            printf("%02X ", (unsigned char)buffer[i]);
        }
        printf("\n");
    }

    // Další sekce (Answer, Authority, Additional) by měly být zpracovány podobně.
    // Toto je ukázka, lze rozšířit podle potřeby:
    printf("====================\n");
}

// Upravená funkce parseDNSMessage
void parseDNSMessage(char *buffer, ssize_t size, bool verbose, const char *srcIP, const char *dstIP)
{
    if ((size_t)size < sizeof(DNSHeader))
    {
        printf("Invalid DNS packet size\n");
        return;
    }

    DNSHeader *dnsHeader = (DNSHeader *)buffer;

    if (verbose)
    {
        printVerboseDNS(dnsHeader, srcIP, dstIP, size, buffer);
    }
    else
    {
        printSimplifiedDNS(dnsHeader, srcIP, dstIP);
    }
}


