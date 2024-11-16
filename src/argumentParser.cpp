#include "../include/argumentParser.h"

void argumentParser::parseArguments(int argc, char *argv[], inputArguments &out)
{
    // Print help if needed.
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

    // Initialize default values (if necessary)
    out.v = false; // Assume there's a field for verbose mode

    // Parse the command-line arguments.
    for (int i = 1; i < argc; ++i)
    {
        std::string argument = argv[i];

        if (argument == "-i")
        {
            if (i + 1 >= argc || argv[i + 1][0] == '-')
            {
                err(1, "Incorrect usage of -i. An interface name is expected.");
            }
            out.interface = argv[i + 1]; // Interface
            out.i = true;                // Set the flag
            ++i;
        }
        else if (argument == "-p")
        {
            if (i + 1 >= argc || argv[i + 1][0] == '-')
            {
                err(1, "Incorrect usage of -p. A PCAP file name is expected.");
            }
            out.pcapFile = argv[i + 1]; // PCAP file
            out.p = true;               // Set the flag
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
                err(1, "Incorrect usage of -d. A domains file name is expected.");
            }
            out.domainsFile = argv[i + 1]; // Assuming out has a field for domains file
            out.d = true;                  // Set the flag
            ++i;
        }
        else if (argument == "-t")
        {
            if (i + 1 >= argc || argv[i + 1][0] == '-')
            {
                err(1, "Incorrect usage of -t. A translations file name is expected.");
            }
            out.translationsFile = argv[i + 1]; // Assuming out has a field for translations file
            out.t = true;                       // Set the flag
            ++i;
        }
        else
        {
            err(1, "Unknown argument: %s\n", argument.c_str());
        }
    }
    //print all arguments
    std::cout << "Arguments: " << std::endl;
    std::cout << "Interface: " << out.interface << std::endl;
    std::cout << "PCAP File: " << out.pcapFile << std::endl;
    std::cout << "Domains File: " << out.domainsFile << std::endl;
    std::cout << "Translations File: " << out.translationsFile << std::endl;
    std::cout << "Verbose: " << out.v << std::endl;
    std::cout << "i: " << out.i << std::endl;
    std::cout << "p: " << out.p << std::endl;
    std::cout << "d: " << out.d << std::endl;
    std::cout << "t: " << out.t << std::endl;
}
