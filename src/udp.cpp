#include "../include/udp.h"

#define PORT 53          // Typically for DNS
#define BUFFER_SIZE 1522 // Maximum size for Ethernet packet

// Declare the global pointer to store the UDPConnection instance
UDPConnection *g_udpConnectionInstance = nullptr;

#define PORT 53          // Typically for DNS
#define BUFFER_SIZE 1522 // Maximum size for Ethernet packet

// Constructor for UDPConnection class
UDPConnection::UDPConnection(const inputArguments &args) : args(args), udp_socket(-1)
{
    // Set the global instance pointer to 'this'
    g_udpConnectionInstance = this;
}

// Destructor for UDPConnection class
UDPConnection::~UDPConnection()
{
    if (udp_socket >= 0)
    {
        close(udp_socket); // Clean up and close the socket
    }
    // Set the global instance pointer to nullptr on destruction
    g_udpConnectionInstance = nullptr;
}

// Public method to start the UDP connection
int UDPConnection::start()
{
    // Step 1: Configure network interface
    if (!configureInterface())
    {
        return -1; // Return if interface configuration fails
    }

    // Step 2: Create the socket
    if (!createSocket())
    {
        return -1; // Return if socket creation fails
    }

    // Register signal handler for graceful termination
    setupSignalHandler();

    // Step 3: Process incoming packets in a loop
    while (true)
    {
        unsigned char buffer[BUFFER_SIZE];
        struct sockaddr_in client_addr;
        socklen_t client_addr_len = sizeof(client_addr);
        memset(buffer, 0, BUFFER_SIZE); // Clear the buffer

        // Receive raw packet (blocking call)
        ssize_t bytes_received = recvfrom(udp_socket, buffer, BUFFER_SIZE, 0,
                                          (struct sockaddr *)&client_addr, &client_addr_len);

        if (bytes_received < 0)
        {
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

    return 0; // This is never reached due to the infinite loop
}

// Private method to handle signal for graceful shutdown
void UDPConnection::handleSignal(int signum)
{
    printf("\nTerminating the server gracefully...\n");
    if (udp_socket >= 0)
    {
        close(udp_socket); // Close the socket if it's open
    }
    exit(signum); // Exit the program
}

// Static method to handle signals from outside the class context
void UDPConnection::signalHandler(int signum, UDPConnection *instance)
{
    instance->handleSignal(signum); // Call the instance's handleSignal method
}

// Method to set up the signal handler
void UDPConnection::setupSignalHandler()
{
    // Use the global instance pointer directly in the signal handler
    signal(SIGINT, [](int signum)
           {
        // Now, we use the global pointer 'g_udpConnectionInstance' directly in the lambda
        if (g_udpConnectionInstance) {
            signalHandler(signum, g_udpConnectionInstance); // Call the signalHandler with the global instance
        } });
}

// Method to configure network interface (dummy for now)
bool UDPConnection::configureInterface()
{
    // Add logic to configure the network interface based on the args.interface
    printf("Configuring network interface: %s\n", args.interface.c_str());
    return true;
}

// Method to create a raw socket
bool UDPConnection::createSocket()
{
    udp_socket = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_IP)); // Create raw socket for IP packets
    if (udp_socket < 0)
    {
        perror("Error: Could not create socket");
        return false;
    }
    return true;
}