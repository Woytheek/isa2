#include "../include/udp.h"

#define PORT 1053       // DNS uses port 53
#define BUFFER_SIZE 512 // Maximum DNS message size over UDP

int udpConnection()
{
    // Step 1: Create a UDP socket
    int udp_socket = socket(AF_INET, SOCK_DGRAM, 0);
    if (udp_socket < 0)
    {
        printf("Error: Could not create socket\n");
        return -1;
    }

    // Step 2: Bind the socket to port 53 (DNS port)
    struct sockaddr_in server_addr;
    memset(&server_addr, 0, sizeof(server_addr));
    server_addr.sin_family = AF_INET;
    server_addr.sin_addr.s_addr = INADDR_ANY; // Listen on all available interfaces
    server_addr.sin_port = htons(PORT);       // Host-to-network byte order for port 53

    if (bind(udp_socket, (struct sockaddr *)&server_addr, sizeof(server_addr)) < 0)
    {
        printf("Error: Bind failed\n");
        close(udp_socket);
        return -1;
    }

    printf("Listening for DNS messages on port %d...\n", PORT);

    // Step 3: Listen for incoming DNS packets
    while (true)
    {
        char buffer[BUFFER_SIZE];
        struct sockaddr_in client_addr;
        socklen_t client_addr_len = sizeof(client_addr);
        memset(buffer, 0, BUFFER_SIZE); // Clear the buffer

        // Receive UDP packet (recvfrom is a blocking call)
        ssize_t bytes_received = recvfrom(udp_socket, buffer, BUFFER_SIZE, 0,
                                          (struct sockaddr *)&client_addr, &client_addr_len);

        if (bytes_received < 0)
        {
            printf("Error: Failed to receive packet\n");
        }
        else
        {
            printf("\nReceived DNS message from %s:%d\n", inet_ntoa(client_addr.sin_addr), ntohs(client_addr.sin_port));

            // Step 4: Parse and print DNS message
            parseDNSMessage(buffer, bytes_received);
        }
    }

    // Close the socket (never reached in this infinite loop)
    close(udp_socket);

    return 0;
}
