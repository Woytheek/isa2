#include "../include/include.h"
#include "../include/udp.h"
#include "../include/argumentParser.h"

int main(int argc, char *argv[])
{
    // Parse input arguments.
    argumentParser parser;
    inputArguments args;
    parser.parseArguments(argc, argv, args);

    udpConnection(args);
}