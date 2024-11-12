#include "../include/include.h"
#include "../include/udp.h"
#include "../include/pcap.h"
#include "../include/argumentParser.h"

int main(int argc, char *argv[])
{
    // Parse input arguments.
    argumentParser parser;
    inputArguments args;
    parser.parseArguments(argc, argv, args);
    if (!args.pcapFile.empty())
    {
        parsePCAPFile(args);
        return 0;
    }

    if (!udpConnection(args))
    {
        std::cerr << "Failed to establish UDP connection!" << std::endl;
        return 1; // return if UDP connection fails
    }

    return 0;
}