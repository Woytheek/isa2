#pragma once

#include "include.h"
#include "argumentParser.h"
#include "dns.h"

int udpConnection(inputArguments args);
void printHeaderInfo(struct pcap_pkthdr *header);
void listInterfaces();