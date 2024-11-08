#include "../include/dns.h"

void printBytes(const unsigned char *data, int size)
{
    for (int i = 0; i < size; ++i)
    {
        // Print each byte in hex format with leading zeros
        printf("%02x", data[i]);
        if (i < size - 1)
        {
            printf(" "); // Print space between bytes
        }
    }
    printf("\n"); // End with a newline
}

int isDNSPacket(const u_char *packet, int length)
{
    // Check if the packet length is sufficient for Ethernet and IP headers
    if (length < 42)
    {             // 14 (Ethernet) + 20 (IP) + 8 (UDP) = 42
        return 0; // Not enough data for a DNS packet
    }

    // Pointer to IP header
    struct ip *ip = (struct ip *)(packet + 14); // Skip Ethernet header
    // Pointer to UDP header
    struct udphdr *udp = (struct udphdr *)(packet + 14 + (ip->ip_hl * 4)); // Skip Ethernet and IP headers

    // Check if the protocol is UDP (17)
    if (ip->ip_p != IPPROTO_UDP)
    {
        return 0; // Not a UDP packet
    }

    // Check if the source or destination port is 53 (DNS)
    if (ntohs(udp->uh_sport) == 53 || ntohs(udp->uh_dport) == 53)
    {
        return 1; // It is a DNS packet
    }

    return 0; // Not a DNS packet
}

void printSimplifiedDNS(DNSHeader *dnsHeader, const char *srcIP, const char *dstIP, char *dateTime)
{
    char qr = (ntohs(dnsHeader->flags) & 0x8000) ? 'R' : 'Q';
    int qdCount = ntohs(dnsHeader->qdCount);
    int anCount = ntohs(dnsHeader->anCount);
    int nsCount = ntohs(dnsHeader->nsCount);
    int arCount = ntohs(dnsHeader->arCount);

    printf("%s %s -> %s (%c %d/%d/%d/%d)\n", dateTime, srcIP, dstIP, qr, qdCount, anCount, nsCount, arCount);
}

void printVerboseDNS(DNSHeader *dnsHeader, const char *srcIP, const char *dstIP, ssize_t size, unsigned char *buffer, char *dateTime)
{
    printf("Timestamp: %s\n", dateTime);
    printf("SrcIP: %s\n", srcIP);
    printf("DstIP: %s\n", dstIP);
    printf("SrcPort: UDP/%d\n", PORT);
    printf("DstPort: UDP\n");

    printf("Identifier: 0x%X\n", ntohs(dnsHeader->id));
    printf("Flags: QR=%d, OPCODE=%d, AA=%d, TC=%d, RD=%d, RA=%d, AD=%d, CD=%d, RCODE=%d\n",
           (ntohs(dnsHeader->flags) & 0x8000) >> 15,
           (ntohs(dnsHeader->flags) & 0x7800) >> 11,
           (ntohs(dnsHeader->flags) & 0x0400) >> 10,
           (ntohs(dnsHeader->flags) & 0x0200) >> 9,
           (ntohs(dnsHeader->flags) & 0x0100) >> 8,
           (ntohs(dnsHeader->flags) & 0x0080) >> 7,
           (ntohs(dnsHeader->flags) & 0x0020) >> 5,
           (ntohs(dnsHeader->flags) & 0x0010) >> 4,
           (ntohs(dnsHeader->flags) & 0x000F));

    if (ntohs(dnsHeader->qdCount) > 0)
    {
        printf("\n[Question Section]\n");
        for (int i = sizeof(DNSHeader); i < size; ++i)
        {
            printf("%c", (unsigned char)buffer[i]);
        }
        printf("\n");
    }

    if (ntohs(dnsHeader->anCount) > 0)
    {
        printf("\n[Answer Section]\n");
        
        printf("\n");
    }

    if (ntohs(dnsHeader->nsCount) > 0)
    {
        printf("\n[Authority Section]\n");
        
        printf("\n");
    }

    if (ntohs(dnsHeader->arCount) > 0)
    {
        printf("\n[Additional Section]\n");
        
        printf("\n");
    }

    printf("====================\n");
}

void parseRawPacket(unsigned char *buffer, ssize_t bufferSize, struct pcap_pkthdr header, inputArguments args)
{
    char dateTime[20];
    struct tm *timeinfo;

    if (args.p)
    {
        // Catched packet from PCAP file
        timeinfo = localtime(&header.ts.tv_sec);
    }
    else
    {
        // Catched live packet
        time_t rawtime;
        time(&rawtime);
        timeinfo = localtime(&rawtime);
    }

    strftime(dateTime, sizeof(dateTime), "%Y-%m-%d %H:%M:%S", timeinfo);
    parseDNSMessage(buffer, bufferSize, dateTime, args.v);
    return;
}

void parseDNSMessage(unsigned char *packet, ssize_t size, char *dateTime, bool v)
{
    // Předpokládáme Ethernetový header (14 bajtů), extrahujeme IP header
    struct ip *ipHeader = (struct ip *)(packet + 14); // Skip Ethernet header

    // Extrakce zdrojové a cílové IP adresy
    char srcIP[INET_ADDRSTRLEN];
    char dstIP[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, &(ipHeader->ip_src), srcIP, INET_ADDRSTRLEN);
    inet_ntop(AF_INET, &(ipHeader->ip_dst), dstIP, INET_ADDRSTRLEN);

    // Přeskočíme Ethernet, IP a UDP headery k dosažení DNS sekce
    unsigned char *dnsPayload = packet + 14 + (ipHeader->ip_hl * 4) + 8; // 8 bajtů pro délku UDP headeru

    // Výpočet velikosti DNS: celková velikost - Ethernet header - IP header - UDP header
    ssize_t dnsSize = size - (14 + (ipHeader->ip_hl * 4) + 8);

    // Zajištění, že velikost DNS paketu je validní
    if (dnsSize < (ssize_t)sizeof(DNSHeader))
    {
        printf("Invalid DNS packet after IP header\n");
        return;
    }

    // Ukazatel na DNS header
    DNSHeader *dnsHeader = (DNSHeader *)dnsPayload;

    // Zkontrolujeme, zda je zapnutý podrobný režim
    if (v)
    {
        // Předáme &header jako ukazatel na strukturu pcap_pkthdr
        printVerboseDNS(dnsHeader, srcIP, dstIP, dnsSize, dnsPayload, dateTime);
    }
    else
    {
        printSimplifiedDNS(dnsHeader, srcIP, dstIP, dateTime);
    }
}
