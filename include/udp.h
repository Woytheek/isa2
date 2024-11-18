/**
 * @file udp.h
 * @author Vojtěch Kuchař xkucha30
 * @brief Defines the UDPConnection class for managing UDP network connections.
 *        Provides methods for setting up, managing, and gracefully shutting down
 *        a UDP connection, including signal handling and socket configuration.
 * @version 1.0
 * @date 2024-11-17
 *
 * @copyright Copyright (c) 2024
 *
 */

#pragma once

#include "include.h"
#include "argumentParser.h"
#include "dns.h"
class UDPConnection;

extern UDPConnection *g_udpConnectionInstance; // Declare a global pointer for UDPConnection instance

class UDPConnection
{
public:
    /**
     * @brief Constructs a UDPConnection object using the provided input arguments.
     *        Initializes necessary properties and sets up the global instance pointer.
     *
     * @param args Input arguments containing configuration for the UDP connection.
     */
    explicit UDPConnection(const inputArguments &args);

    /**
     * @brief Destructor for the UDPConnection class.
     *        Cleans up by closing the socket if it's open and resets the global instance pointer.
     */
    ~UDPConnection();

    /**
     * @brief Starts the UDP connection, creates raw sockets, and processes incoming packets.
     *
     * This function creates both IPv4 and IPv6 raw sockets, sets up a signal handler for graceful termination,
     * and enters a loop where it waits for incoming packets on either socket using `select`. Upon receiving a packet,
     * it checks if the packet is a DNS packet, and if so, processes the packet using a DNS parser.
     *
     * @return Returns 0 on successful completion (this is never reached due to the infinite loop).
     */
    int start();

    /**
     * @brief Static method to handle signals from outside the class context.
     *        This method redirects the signal handling to the instance method.
     *
     * @param signum Signal number (e.g., SIGINT).
     * @param instance Pointer to the UDPConnection instance to call the handleSignal method on.
     */
    static void signalHandler(int signum, UDPConnection *instance);

private:
    inputArguments args; // Parsed input arguments
    int udp_socket;      // UDP socket descriptor
    int udp_socket6;     // UDP socket descriptor for IPv6
    std::string ipStr;   // IP address as string

    /**
     * @brief Creates the raw sockets needed for UDP communication.
     *
     * @return bool Returns true if sockets creation is successful, false otherwise.
     */
    bool createSocket();

    /**
     * @brief Sets up the signal handler for graceful termination of the server.
     *        Uses the global UDPConnection instance pointer in the signal handler.
     */
    void setupSignalHandler();

    /**
     * @brief Handles a signal (e.g., SIGINT) for graceful termination of the UDP connection.
     *
     * @param signum Signal number (e.g., SIGINT).
     */
    void handleSignal(int signum);
};