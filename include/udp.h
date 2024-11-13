#pragma once

#include "include.h"
#include "argumentParser.h"
#include "dns.h"
class UDPConnection;
// Declare a global pointer for UDPConnection instance
extern UDPConnection *g_udpConnectionInstance;

class UDPConnection
{
public:
    explicit UDPConnection(const inputArguments &args); // Constructor
    ~UDPConnection();                                   // Destructor

    int start(); // Start the UDP connection

    // This function is now public so the static signal handler can call it
    static void signalHandler(int signum, UDPConnection *instance);

private:
    inputArguments args; // Parsed input arguments
    int udp_socket;      // UDP socket descriptor
    std::string ipStr;   // IP address as string

    bool configureInterface(); // Configure network interface
    bool createSocket();       // Create raw socket

    // This method remains private
    void handleSignal(int signum); // Signal handler for graceful shutdown

    // Registering the signal handler function
    void setupSignalHandler();
};