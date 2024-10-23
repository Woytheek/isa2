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
    int dnsPacketCount = 0;
    int packetCount = 0;
    while ((packet = pcap_next(handle, &header)) != NULL)
    {
        packetCount++;
        if (isDNSPacket(packet, header.len))
        {
            dnsPacketCount++;

            // Extract the IP header
            struct ip *ipHeader = (struct ip *)(packet + 14); // Assuming Ethernet header (14 bytes)

            // Extract source and destination IP addresses
            char srcIP[INET_ADDRSTRLEN];
            char dstIP[INET_ADDRSTRLEN];
            inet_ntop(AF_INET, &(ipHeader->ip_src), srcIP, INET_ADDRSTRLEN);
            inet_ntop(AF_INET, &(ipHeader->ip_dst), dstIP, INET_ADDRSTRLEN);

            // Extract and print DNS information
            parseDNSMessage((char *)packet + 14 + (ipHeader->ip_hl * 4), // Skip Ethernet and IP headers
                            header.len - (14 + (ipHeader->ip_hl * 4)),   // Remaining size for DNS
                            args.verbose,
                            srcIP,
                            dstIP);
        }
    }

    // After processing all packets, print the count of DNS packets
    printf("Total packets: %d, DNS packets: %d\n", packetCount, dnsPacketCount);

    pcap_close(handle);
    return 0;
}
