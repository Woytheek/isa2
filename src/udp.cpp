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
        struct sockaddr_in client_addr;   // For IPv4
        struct sockaddr_in6 client_addr6; // For IPv6
        socklen_t client_addr_len = sizeof(client_addr);
        socklen_t client_addr_len6 = sizeof(client_addr6);

        fd_set read_fds;
        FD_ZERO(&read_fds);
        FD_SET(udp_socket, &read_fds);
        FD_SET(udp_socket6, &read_fds);

        // Wait for either socket to be ready for reading
        int max_fd = std::max(udp_socket, udp_socket6);
        int ready_count = select(max_fd + 1, &read_fds, nullptr, nullptr, nullptr);

        if (ready_count < 0)
        {
            std::cout << "Select error: " << strerror(errno) << std::endl;
            break;
        }

        // Handle incoming data from the IPv4 socket if it's ready.
        if (FD_ISSET(udp_socket, &read_fds))
        {
            ssize_t bytes_received = recvfrom(udp_socket, buffer, BUFFER_SIZE, 0,
                                              (struct sockaddr *)&client_addr, &client_addr_len);
            if (bytes_received > 0)
            {
                struct pcap_pkthdr header;
                DNSParser parser(args);
                int offset = parser.isDNSPacket(buffer, bytes_received);
                if (offset != -1)
                {
                    parser.parseRawPacket(buffer, bytes_received, header, offset);
                }
            }
        }

        // Handle incoming data from the IPv6 socket if it's ready.
        if (FD_ISSET(udp_socket6, &read_fds))
        {
            ssize_t bytes_received6 = recvfrom(udp_socket6, buffer, BUFFER_SIZE, 0,
                                               (struct sockaddr *)&client_addr6, &client_addr_len6);
            if (bytes_received6 > 0)
            {
                struct pcap_pkthdr header;
                DNSParser parser(args);
                int offset = parser.isDNSPacket(buffer, bytes_received6);
                if (offset != -1)
                {
                    parser.parseRawPacket(buffer, bytes_received6, header, offset);
                }
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
    udp_socket6 = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_IPV6));

    if (udp_socket < 0)
    {
        std::cout << "IPv4 Socket creation failed" << std::endl;
        return false;
    }
    if (udp_socket6 < 0)
    {
        std::cout << "IPv6 Socket creation failed" << std::endl;
        return false;
    }

    return true;
}