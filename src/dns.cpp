#include "../include/dns.h"

void printBytes(char *data, int size)
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

// Funkce pro zjednodušený výpis DNS zpráv
void printSimplifiedDNS(DNSHeader *dnsHeader, const char *srcIP, const char *dstIP, struct pcap_pkthdr *header)
{
    // Formátování časové značky z `pcap_pkthdr`
    struct tm *timeinfo;
    char dateTime[20];
    timeinfo = localtime(&header->ts.tv_sec);                            // Převod sekund na lokální čas
    strftime(dateTime, sizeof(dateTime), "%Y-%m-%d %H:%M:%S", timeinfo); // Formátování do řetězce

    // Výpis DNS informací
    char qr = (ntohs(dnsHeader->flags) & 0x8000) ? 'R' : 'Q';
    int qdCount = ntohs(dnsHeader->qdCount);
    int anCount = ntohs(dnsHeader->anCount);
    int nsCount = ntohs(dnsHeader->nsCount);
    int arCount = ntohs(dnsHeader->arCount);

    printf("%s %s -> %s (%c %d/%d/%d/%d)\n",
           dateTime, srcIP, dstIP, qr, qdCount, anCount, nsCount, arCount);
}

// Funkce pro detailní výpis DNS zpráv
void printVerboseDNS(DNSHeader *dnsHeader, const char *srcIP, const char *dstIP, ssize_t size, char *buffer, struct pcap_pkthdr *header)
{
    // Získání timestampu z pcap_pkthdr
    struct tm *timeinfo;
    char dateTime[20];
    timeinfo = localtime(&header->ts.tv_sec); // Používá tv_sec z pcap_pkthdr
    strftime(dateTime, sizeof(dateTime), "%Y-%m-%d %H:%M:%S", timeinfo);

    printf("Timestamp: %s.%06ld\n", dateTime, header->ts.tv_usec); // Přidání mikrosekund
    printf("SrcIP: %s\n", srcIP);
    printf("DstIP: %s\n", dstIP);
    printf("SrcPort: UDP/53\n");
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

    printf("\n[Question Section]\n");
    if (ntohs(dnsHeader->qdCount) > 0)
    {
        for (int i = sizeof(DNSHeader); i < size; ++i)
        {
            printf("%02X ", (unsigned char)buffer[i]);
        }
        printf("\n");
    }

    printf("====================\n");
}

void parseDNSMessage(char *packet, ssize_t size, struct pcap_pkthdr header, bool verbose)
{
    // Předpokládáme Ethernetový header (14 bajtů), extrahujeme IP header
    struct ip *ipHeader = (struct ip *)(packet + 14); // Skip Ethernet header

    // Extrakce zdrojové a cílové IP adresy
    char srcIP[INET_ADDRSTRLEN];
    char dstIP[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, &(ipHeader->ip_src), srcIP, INET_ADDRSTRLEN);
    inet_ntop(AF_INET, &(ipHeader->ip_dst), dstIP, INET_ADDRSTRLEN);

    // Přeskočíme Ethernet, IP a UDP headery k dosažení DNS sekce
    char *dnsPayload = packet + 14 + (ipHeader->ip_hl * 4) + 8; // 8 bajtů pro délku UDP headeru

    // Výpočet velikosti DNS: celková velikost - Ethernet header - IP header - UDP header
    ssize_t dnsSize = size - (14 + (ipHeader->ip_hl * 4) + 8);

    printBytes(packet, size);
    printf("size: %ld\n", size);
    printf("dnsSize: %ld\n", dnsSize);
    printf("ipHeader->ip_hl: %d\n", ipHeader->ip_hl);
    printf("(ssize_t)sizeof(DNSHeader): %ld\n", (ssize_t)sizeof(DNSHeader));

    // Zajištění, že velikost DNS paketu je validní
    if (dnsSize < (ssize_t)sizeof(DNSHeader))
    {
        printf("Invalid DNS packet after IP header\n");
        return;
    }

    // Ukazatel na DNS header
    DNSHeader *dnsHeader = (DNSHeader *)dnsPayload;

    // Zkontrolujeme, zda je zapnutý podrobný režim
    if (verbose)
    {
        // Předáme &header jako ukazatel na strukturu pcap_pkthdr
        printVerboseDNS(dnsHeader, srcIP, dstIP, dnsSize, dnsPayload, &header);
    }
    else
    {
        printSimplifiedDNS(dnsHeader, srcIP, dstIP, &header);
    }
}
