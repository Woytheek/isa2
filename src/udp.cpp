#include "../include/udp.h"
#include "../include/dns.h"

int udp_socket; // Global variable for the UDP socket

// Signal handler for SIGINT
void signalHandler(int signum)
{
    printf("\nTerminating the DNS server gracefully...\n");
    if (udp_socket >= 0) {
        close(udp_socket); // Close the socket if it's open
    }
    exit(signum); // Exit the program
}

int udpConnection(inputArguments args)
{
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
    server_addr.sin_addr.s_addr = INADDR_ANY; // Listen on all available interfaces
    server_addr.sin_port = htons(PORT); // Host-to-network byte order for port 1053

    if (bind(udp_socket, (struct sockaddr *)&server_addr, sizeof(server_addr)) < 0)
    {
        perror("Error: Bind failed");
        close(udp_socket);
        return -1;
    }

    printf("Listening for DNS messages on port %d...\n", PORT);

    // Register signal handler for SIGINT
    signal(SIGINT, signalHandler);

    // Set a timeout for recvfrom
    struct timeval tv;
    tv.tv_sec = 1;  // 1 second timeout
    tv.tv_usec = 0;

    if (setsockopt(udp_socket, SOL_SOCKET, SO_RCVTIMEO, (const char*)&tv, sizeof(tv)) < 0) {
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
            if (errno == EWOULDBLOCK) {
                // Timeout occurred, continue to loop
                continue; 
            }
            perror("Error: Failed to receive packet");
        }
        else
        {
            parseDNSMessage(buffer, bytes_received, args.verbose);
        }
    }

    // Close the socket (never reached in this infinite loop)
    close(udp_socket);
    return 0;
}
