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
#include <pcap.h>
#include <netinet/ip.h>
#include <netinet/udp.h>

using namespace std;
