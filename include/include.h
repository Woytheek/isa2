/**
 * @file include.h
 * @author Vojtěch Kuchař xkucha30
 * @brief Includes all the libraries that are used in the project.
 * @version 1.0
 * @date 2024-11-17
 *
 * @copyright Copyright (c) 2024
 *
 */

#pragma once

#include <set>
#include <stdio.h>
#include <pcap.h>
#include <iostream>
#include <cstring>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <err.h>
#include <signal.h>
#include <stdlib.h>
#include <netinet/ip.h>
#include <netinet/ip6.h>
#include <netinet/udp.h>
#include <string.h>
#include <ifaddrs.h>
#include <sys/time.h>
#include <net/if.h>
#include <string>
#include <linux/if_ether.h>
#include <cstdint>
#include <vector>
#include <cstdint>
#include <sstream>
#include <memory>
#include <fstream>
#include <sstream>
#include <string>
#include <algorithm>
#include <cctype>

using namespace std;

#define PORT 53 // DNS uses port 1053
