/**
 * @file argumentParser.h
 * @author Vojtěch Kuchař xkucha30
 * @brief Defines the inputArguments structure and the argumentParser class for
 *        parsing and handling command-line arguments.
 *        Provides functionality to extract and store input arguments, such as
 *        interface names, PCAP files, and domain translation files.
 * @version 1.0
 * @date 2024-11-17
 *
 * @copyright Copyright (c) 2024
 *
 */

#pragma once

#include "include.h"

// Struct for storing input arguments.
struct inputArguments
{
    string interface;        // Name of the interface to listen on
    string pcapFile;         // Name of the PCAP file to process
    string domainsFile;      // Name of the domains file
    string translationsFile; // Name of the translations file

    bool i = 0; // Flag for interface
    bool p = 0; // Flag for PCAP file
    bool v = 0; // Flag for verbose
    bool d = 0; // Flag for domains file
    bool t = 0; // Flag for translations file
};

class argumentParser
{
public:
    /**
     * @brief Parses the command-line arguments and stores them in the provided structure.
     *        This function processes various flags (e.g., `-i`, `-p`, `-v`, `-d`, `-t`) and
     *        stores the respective values in the `inputArguments` structure. It also
     *        handles the `-h` or `--help` flag to display usage instructions.
     *
     * @param argc The number of command-line arguments.
     * @param argv The array of command-line arguments.
     * @param out The structure to store the parsed arguments.
     */
    static void parseArguments(int argc, char *argv[], inputArguments &out);
};
