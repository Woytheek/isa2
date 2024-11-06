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

    listInterfaces(); // TODO

    udpConnection(args);
    return 0;
}