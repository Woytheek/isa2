#include "../include/udp.h"
#include "../include/dns.h"
#include <sys/time.h>

int udp_socket; // Global variable for the UDP socket

// Signal handler for SIGINT
void signalHandler(int signum)
{
    printf("\nTerminating the DNS server gracefully...\n");
    if (udp_socket >= 0)
    {
        close(udp_socket); // Close the socket if it's open
    }
    exit(signum); // Exit the program
}

void printHeaderInfo(struct pcap_pkthdr *header)
{
    // Convert timestamp to formatted time
    char time_buf[64];
    struct tm *tm_info = localtime(&header->ts.tv_sec);
    strftime(time_buf, sizeof(time_buf), "%Y-%m-%d %H:%M:%S", tm_info);

    // Print packet header information
    printf("Packet capture info:\n");
    printf(" - Timestamp: %s.%06ld\n", time_buf, header->ts.tv_usec); // Microseconds
    printf(" - Length of packet (len): %u bytes\n", header->len);
    printf(" - Captured length (caplen): %u bytes\n", header->caplen);

    printf(" - Header bytes: ");
    unsigned char *byte_ptr = (unsigned char *)header;
    for (size_t i = 0; i < sizeof(struct pcap_pkthdr); i++)
    {
        printf("%02X ", byte_ptr[i]);
    }
    printf("\n");
}

void listInterfaces()
{
    struct ifaddrs *ifaddr, *ifa;
    if (getifaddrs(&ifaddr) == -1)
    {
        perror("getifaddrs");
        exit(EXIT_FAILURE);
    }

    printf("Available network interfaces: ");
    for (ifa = ifaddr; ifa != NULL; ifa = ifa->ifa_next)
    {
        if (ifa->ifa_addr == NULL)
            continue; // Skip if the address is NULL

        // Print only for IPv4 and IPv6 addresses
        if (ifa->ifa_addr->sa_family == AF_INET || ifa->ifa_addr->sa_family == AF_INET6)
        {
            printf("%s ", ifa->ifa_name); // Print the interface name
        }
    }

    freeifaddrs(ifaddr); // Free the memory allocated by getifaddrs
    printf("\n");
}

int udpConnection(inputArguments args)
{

    // Step 1: Check if the interface exists and get its IP address
    struct ifaddrs *ifaddr, *ifa;
    char ipStr[INET_ADDRSTRLEN]; // Buffer to hold the IP string
    int found = 0;

    if (getifaddrs(&ifaddr) == -1)
    {
        perror("Error: getifaddrs failed");
        return -1;
    }

    // Iterate through the list of interfaces
    for (ifa = ifaddr; ifa != NULL; ifa = ifa->ifa_next)
    {
        if (ifa->ifa_addr == NULL)
        {
            continue; // Skip if the address is NULL
        }

        // Check if the current interface matches the requested interface
        if (strcmp(ifa->ifa_name, args.interface.c_str()) == 0)
        {
            if (ifa->ifa_addr->sa_family == AF_INET)
            { // Check for IPv4
                struct sockaddr_in *addr = (struct sockaddr_in *)ifa->ifa_addr;
                inet_ntop(AF_INET, &addr->sin_addr, ipStr, sizeof(ipStr));
                found = 1; // Mark that we found the interface
                break;     // Break once we find the interface
            }
        }
    }

    freeifaddrs(ifaddr); // Free the allocated memory

    if (!found)
    {
        fprintf(stderr, "Error: Interface %s not found\n", args.interface.c_str());
        return -1; // Interface not found
    }

    // Step 1: Create a UDP socket
    udp_socket = socket(AF_INET, SOCK_DGRAM, 0);
    if (udp_socket < 0)
    {
        perror("Error: Could not create socket");
        return -1;
    }

    // Step 2: Bind the socket to the IP address of eth0
    struct sockaddr_in server_addr;
    memset(&server_addr, 0, sizeof(server_addr));
    server_addr.sin_family = AF_INET;
    server_addr.sin_addr.s_addr = inet_addr(ipStr); // Listen on selected interface
    server_addr.sin_port = htons(PORT);

    if (bind(udp_socket, (struct sockaddr *)&server_addr, sizeof(server_addr)) < 0)
    {
        perror("Error: Bind failed");
        close(udp_socket);
        return -1;
    }

    printf("Listening for DNS messages on %s (%s)...\n", ipStr, args.interface.c_str());

    // Register signal handler for SIGINT
    signal(SIGINT, signalHandler);

    // Set a timeout for recvfrom
    struct timeval tv;
    tv.tv_sec = 1; // 1 second timeout
    tv.tv_usec = 0;

    if (setsockopt(udp_socket, SOL_SOCKET, SO_RCVTIMEO, (const char *)&tv, sizeof(tv)) < 0)
    {
        perror("Error: Setting socket options failed");
        close(udp_socket);
        return -1;
    }

    // Step 3: Listen for incoming DNS packets
    while (1)
    {
        char buffer[BUFFER_SIZE];
        struct sockaddr_in client_addr;
        socklen_t client_addr_len = sizeof(client_addr);
        memset(buffer, 0, BUFFER_SIZE); // Clear the buffer

        // Receive UDP packet (recvfrom is a blocking call, but with timeout)
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
            // Create a pcap_pkthdr and set values
            struct pcap_pkthdr header;
            header.len = bytes_received;
            header.caplen = bytes_received;

            gettimeofday(&header.ts, NULL); // Get current timestamp

            printHeaderInfo(&header);
            // Call parseDNSMessage with the correct parameters
            parseDNSMessage(buffer, bytes_received, header, args.verbose);
        }
    }

    // Close the socket (never reached in this infinite loop)
    close(udp_socket);
    return 0;
}
