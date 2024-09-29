#include "../include/argumentParser.h"

void argumentParser::parseArguments(int argc, char *argv[], inputArguments &out)
{
    // Print help if needed.
    if (argc == 2 && (string(argv[1]) == "-h" || string(argv[1]) == "--help"))
    {
        printf("Usage: %s [-p port] -f file\n", argv[0]);
        exit(0);
    }

    // Parse the port.
    for (int i = 1; i < argc; ++i)
    {
        string argument = argv[i];
        if (argument == "-p")
        {
            if (i + 1 >= argc || argv[i + 1][0] == '-')
            {
                err(1, "Incorrect usage of -p. A port number is expected.");
            }
            try
            {
                out.port = stoi(argv[i + 1]);
            }
            catch (const invalid_argument &e)
            {
                err(1, "Invalid port number. Please provide a valid port number after -p.");
            }
            ++i;
        }
        else
        {
            err(1, "Unkwnown argument: %s\n", argument.c_str());
        }
    }
}