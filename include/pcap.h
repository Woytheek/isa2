/**
 * @file pcap.h
 * @author Vojtěch Kuchař xkucha30
 * @brief Defines functionality for opening and parsing PCAP files.
 *        Includes methods for extracting DNS packets and managing PCAP file operations.
 * @version 1.0
 * @date 2024-11-17
 *
 * @copyright Copyright (c) 2024
 *
 */

#pragma once

#include "include.h"
#include "dns.h"
#include "argumentParser.h"

class PCAPParser
{
public:
    /**
     * @brief Constructor for the PCAPParser class, initializing with the provided input arguments.
     *        Initializes the error buffer and prepares the PCAP handle for later use.
     *
     * @param args The input arguments structure that contains the PCAP file and parsing options.
     */
    explicit PCAPParser(const inputArguments &args);

    /**
     * @brief Parses the entire PCAP file, extracting DNS packets and processing them.
     *        Loops through the packets, checks for DNS packets, and passes them to the DNSParser for further processing.
     *        Closes the PCAP file after parsing all packets.
     *
     * @return 0 if the file was successfully parsed, or 1 if an error occurred.
     */
    int parseFile();

private:
    char errbuf[PCAP_ERRBUF_SIZE]; // Error buffer and PCAP handle
    pcap_t *handle;                // PCAP handle for reading packetss
    inputArguments args;           // Arguments containing file path and parsing options

    /**
     * @brief Attempts to open the PCAP file in offline mode.
     *        Initializes the PCAP handle and prepares it for packet parsing.
     *
     * @return True if the file was successfully opened, false otherwise.
     */
    bool openFile();

    /**
     * @brief Closes the PCAP file and cleans up any resources associated with the handle.
     *        Sets the PCAP handle to null after closing the file.
     */
    void closeFile();

    /**
     * @brief Determines if a given packet is a DNS packet and returns the DNS packet offset.
     *        Calls the `isDNSPacket` function from the DNSParser class to check if a packet is DNS.
     *
     * @param packet The raw packet data.
     * @param length The length of the packet.
     * @return The offset of the DNS data within the packet if it is a DNS packet, or -1 if not.
     */
    int getDNSOffset(const unsigned char *packet, int length) const;
};