#include "../include/udp.h"

#define PORT 53          // Typically for DNS
#define BUFFER_SIZE 1522 // Maximum size for Ethernet packet

int udp_socket; // Global variable for the socket

void signalHandler(int signum)
{
    printf("\nTerminating the server gracefully...\n");
    if (udp_socket >= 0)
    {
        close(udp_socket); // Close the socket if it's open
    }
    exit(signum); // Exit the program
}

int udpConnection(inputArguments args)
{
    struct ifaddrs *ifaddr, *ifa;
    char ipStr[INET_ADDRSTRLEN]; // Buffer to hold the IP string
    int found = 0;

    // Step 1: Check if the interface exists and get its IP address
    if (getifaddrs(&ifaddr) == -1)
    {
        perror("Error: getifaddrs failed");
        return -1;
    }

    for (ifa = ifaddr; ifa != NULL; ifa = ifa->ifa_next)
    {
        if (ifa->ifa_addr == NULL)
        {
            continue; // Skip if the address is NULL
        }

        if (strcmp(ifa->ifa_name, args.interface.c_str()) == 0)
        {
            if (ifa->ifa_addr->sa_family == AF_INET)
            { // Check for IPv4
                struct sockaddr_in *addr = (struct sockaddr_in *)ifa->ifa_addr;
                inet_ntop(AF_INET, &addr->sin_addr, ipStr, sizeof(ipStr));
                found = 1; // Mark that we found the interface
                break;
            }
        }
    }

    freeifaddrs(ifaddr); // Free the allocated memory

    if (!found)
    {
        fprintf(stderr, "Error: Interface %s not found\n", args.interface.c_str());
        return -1; // Interface not found
    }

    // Step 2: Create a raw socket to capture all packets (Ethernet, IP, UDP, DNS)
    udp_socket = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_IP)); // Raw socket for IP packets
    if (udp_socket < 0)
    {
        perror("Error: Could not create socket");
        return -1;
    }

    printf("Listening for DNS messages on %s (%s)...\n", ipStr, args.interface.c_str());

    // Register signal handler for SIGINT
    signal(SIGINT, signalHandler);

    // Set a timeout for recvfrom (this will be for raw socket reception)
    struct timeval tv;
    tv.tv_sec = 1; // 1-second timeout
    tv.tv_usec = 0;

    if (setsockopt(udp_socket, SOL_SOCKET, SO_RCVTIMEO, (const char *)&tv, sizeof(tv)) < 0)
    {
        perror("Error: Setting socket options failed");
        close(udp_socket);
        return -1;
    }

    // Step 3: Listen for incoming packets (Ethernet, IP, UDP, DNS)
    while (1)
    {
        unsigned char buffer[BUFFER_SIZE];
        struct sockaddr_in client_addr;
        socklen_t client_addr_len = sizeof(client_addr);
        memset(buffer, 0, BUFFER_SIZE); // Clear the buffer

        // Receive raw packet (recvfrom is a blocking call, but with timeout)
        ssize_t bytes_received = recvfrom(udp_socket, buffer, BUFFER_SIZE, 0,
                                          (struct sockaddr *)&client_addr, &client_addr_len);

        if (bytes_received < 0)
        {
            if (errno == EWOULDBLOCK)
            {
                // Timeout occurred, continue to loop
                continue;
            }
            perror("Error: Failed to receive packet");
        }
        else
        {
            struct pcap_pkthdr header;
            int offset = isDNSPacket(buffer, bytes_received);
            if (offset != -1)
            {
                parseRawPacket(buffer, bytes_received, header, args, offset);
            }
        }
    }

    // Close the socket (never reached in this infinite loop)
    close(udp_socket);
    return 0;
}
