#include "../include/pcap.h"

// Function to check if the packet is a DNS packet
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

int parsePCAPFile(inputArguments args)
{
    // Open the PCAP file
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t *handle = pcap_open_offline(args.pcapFile.c_str(), errbuf);
    if (handle == NULL)
    {
        fprintf(stderr, "Could not open file %s: %s\n", args.pcapFile.c_str(), errbuf);
        return 1;
    }

    struct pcap_pkthdr header;
    const u_char *packet;
    while ((packet = pcap_next(handle, &header)) != NULL)
    {
        if (isDNSPacket(packet, header.len))
        {
            printf("=======HERE=======\n");
            // Extract and print DNS information
            
        }
    }

    pcap_close(handle);
    return 0;
}