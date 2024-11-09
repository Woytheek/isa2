#include "../include/pcap.h"

int parsePCAPFile(inputArguments args)
{
    // Open the PCAP file
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t *handle = pcap_open_offline(args.pcapFile.c_str(), errbuf);
    if (handle == NULL)
    {
        fprintf(stderr, "Could not open file %s: %s\n", args.pcapFile.c_str(), errbuf);
        printf("Error: %s\n", pcap_geterr(handle));
        return 1;
    }

    struct pcap_pkthdr header;
    const unsigned char *packet;

    // Loop to read each packet
    while ((packet = pcap_next(handle, &header)) != NULL)
    {
        // If this is a DNS packet, process it
        if (isDNSPacket(packet, header.len))
        {
            parseRawPacket((unsigned char *)packet, header.len, header, args);
        }
    }

    pcap_close(handle);
    return 0;
}
