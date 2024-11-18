/**
 * @file argumentParser.cpp
 * @author Vojtěch Kuchař xkucha30
 * @brief Implements functionality to extract and store input arguments, such as
 *        interface names, PCAP files, and domain translation files.
 * @version 1.0
 * @date 2024-11-17
 *
 * @copyright Copyright (c) 2024
 *
 */

#include "../include/argumentParser.h"

void argumentParser::parseArguments(int argc, char *argv[], inputArguments &out)
{
    if (argc == 2 && (std::string(argv[1]) == "-h" || std::string(argv[1]) == "--help"))
    {
        printf("Usage: %s (-i <interface> | -p <pcapfile>) [-v] [-d <domainsfile>] [-t <translationsfile>]\n"
               "Parameters:\n"
               "  -i <interface>        - The name of the interface on which the program will listen.\n"
               "  -p <pcapfile>         - The name of the PCAP file that the program will process.\n"
               "  -v                    - Enable \"verbose\" mode: prints detailed information about DNS messages.\n"
               "  -d <domainsfile>      - The name of the file containing domain names.\n"
               "  -t <translationsfile> - The name of the file containing translations of domain names to IP addresses.\n",
               argv[0]);
        exit(0);
    }

    out.v = false;

    // Parse the command-line arguments.
    for (int i = 1; i < argc; ++i)
    {
        std::string argument = argv[i];

        if (argument == "-i")
        {
            if (i + 1 >= argc || argv[i + 1][0] == '-')
            {
                std::cerr << "Incorrect usage of -i. An interface name is expected." << std::endl;
                exit(1);
            }
            out.interface = argv[i + 1]; // Interface
            out.i = true;                // Set the flag
            ++i;
        }
        else if (argument == "-p")
        {
            if (i + 1 >= argc || argv[i + 1][0] == '-')
            {
                std::cerr << "Incorrect usage of -p. A PCAP file name is expected." << std::endl;
                exit(1);
            }
            out.pcapFile = argv[i + 1]; // PCAP file
            out.p = true;
            ++i;
        }
        else if (argument == "-v")
        {
            out.v = true; // Set verbose flag to true
        }
        else if (argument == "-d")
        {
            if (i + 1 >= argc || argv[i + 1][0] == '-')
            {
                std::cerr << "Incorrect usage of -d. A domains file name is expected." << std::endl;
                exit(1);
            }
            out.domainsFile = argv[i + 1]; // Domains file
            out.d = true;
            ++i;
        }
        else if (argument == "-t")
        {
            if (i + 1 >= argc || argv[i + 1][0] == '-')
            {
                std::cerr << "Incorrect usage of -t. A translations file name is expected." << std::endl;
                exit(1);
            }
            out.translationsFile = argv[i + 1]; // Translations file
            out.t = true;
            ++i;
        }
        else
        {
            std::cerr << "Unknown argument: " << argument << std::endl;
            exit(1);
        }
    }
}
