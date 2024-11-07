#pragma once
#include <stdio.h>
#include <pcap.h>
#include <iostream>
#include <cstring>      // For memset, memcpy
#include <sys/socket.h> // For socket, bind, recvfrom
#include <netinet/in.h> // For sockaddr_in, htons, htonl
#include <arpa/inet.h>  // For inet_addr
#include <unistd.h>     // For close
#include <err.h>
#include <signal.h>
#include <stdlib.h>
#include <netinet/ip.h>
#include <netinet/udp.h>
#include <string.h>
#include <ifaddrs.h>
#include <sys/time.h>
#include <net/if.h>
#include <string>
#include <linux/if_ether.h> // Include this header for ETH_P_IP

using namespace std;

#define PORT 53         // DNS uses port 1053
