/**
 * @file udp.cpp
 * @author Vojtěch Kuchař xkucha30
 * @brief Implements the UDPConnection class for managing UDP network connections.
 * @version 1.0
 * @date 2024-11-17
 *
 * @copyright Copyright (c) 2024
 *
 */

#include "../include/udp.h"

#define PORT 53          // Typically for DNS
#define BUFFER_SIZE 1522 // Maximum size for Ethernet packet

// Declare the global pointer to store the UDPConnection instance
UDPConnection *g_udpConnectionInstance = nullptr;

UDPConnection::UDPConnection(const inputArguments &args) : args(args), udp_socket(-1)
{
    // Set the global instance pointer to 'this'
    g_udpConnectionInstance = this;
}

UDPConnection::~UDPConnection()
{
    if (udp_socket >= 0)
    {
        close(udp_socket);
    }
    g_udpConnectionInstance = nullptr;
}

int UDPConnection::start()
{
    if (!createSocket())
    {
        return -1;
    }

    // Register signal handler for graceful termination
    setupSignalHandler();

    // Process incoming packets in a loop
    while (true)
    {
        unsigned char buffer[BUFFER_SIZE];
        struct sockaddr_in client_addr;
        socklen_t client_addr_len = sizeof(client_addr);
        memset(buffer, 0, BUFFER_SIZE); // Clear the buffer

        ssize_t bytes_received = recvfrom(udp_socket, buffer, BUFFER_SIZE, 0,
                                          (struct sockaddr *)&client_addr, &client_addr_len);

        if (bytes_received < 0)
        {
            perror("Error: Failed to receive packet");
        }
        else
        {
            struct pcap_pkthdr header;

            DNSParser parser(args);
            int offset = parser.isDNSPacket(buffer, bytes_received);
            if (offset != -1)
            {
                // Zavolání funkce pro zpracování paketu
                parser.parseRawPacket(buffer, bytes_received, header, offset);
            }
        }
    }

    return 0; // This is never reached due to the infinite loop
}

void UDPConnection::handleSignal(int signum)
{
    printf("\nTerminating the server gracefully...\n");
    if (udp_socket >= 0)
    {
        close(udp_socket); // Close the socket if it's open
    }
    exit(signum);
}

void UDPConnection::signalHandler(int signum, UDPConnection *instance)
{
    instance->handleSignal(signum);
}

void UDPConnection::setupSignalHandler()
{
    // Use the global instance pointer directly in the signal handler
    signal(SIGINT, [](int signum)
           {
        // Global pointer 'g_udpConnectionInstance' directly in the lambda
        if (g_udpConnectionInstance) {
            signalHandler(signum, g_udpConnectionInstance); // Call the signalHandler with the global instance
        } });
}

bool UDPConnection::createSocket()
{
    udp_socket = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_IP));
    if (udp_socket < 0)
    {
        perror("Error: Could not create socket");
        return false;
    }
    return true;
}