#pragma once

#include "include.h"

// Struct for storing input arguments.
struct inputArguments
{
    string interface;        // Name of the interface to listen on
    string pcapFile;         // Name of the PCAP file to process
    string domainsFile;      // Name of the domains file
    string translationsFile; // Name of the translations file

    bool i; // Flag for interface
    bool p; // Flag for PCAP file
    bool v; // Flag for verbose
    bool d; // Flag for domains file
    bool t; // Flag for translations file
};

class argumentParser
{
public:
    /**
     * @brief Handles the input arguments. Prints help if needed.
     *
     * @param argc Length of argv.
     * @param argv Array of arguments.
     * @param out Struct for storing the arguments.
     */
    static void parseArguments(int argc, char *argv[], inputArguments &out);
};
