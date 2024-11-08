#pragma once

#include "include.h"
#include "argumentParser.h"
#include "dns.h"

int udpConnection(inputArguments args);
void parseRawPacket(unsigned char *buffer, ssize_t bufferSize, inputArguments args);