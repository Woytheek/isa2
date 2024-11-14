#pragma once

#include "include.h"
#include "argumentParser.h"
#include "file.h"


void loadArguments(inputArguments arguments);

// DNS header structure
struct DNSHeader
{
    uint16_t id;      // Transaction ID
    uint16_t flags;   // Flags and response codes
    uint16_t qdCount; // Number of questions
    uint16_t anCount; // Number of answers
    uint16_t nsCount; // Number of authority records
    uint16_t arCount; // Number of additional records
};

struct QuestionSection
{
    std::string qName;
    uint16_t qType;
    uint16_t qClass;
};

struct ResourceRecord
{
    std::string name;
    uint16_t type;
    uint16_t classCode;
    uint32_t ttl;
    uint16_t rdLength;
    std::vector<uint8_t> rData;

    size_t rDataOffset;
    bool skip = false;
};

struct DNSSections
{
    std::vector<QuestionSection> questions;
    std::vector<ResourceRecord> answers;
    std::vector<ResourceRecord> authorities;
    std::vector<ResourceRecord> additionals;
};

std::string readDomainName(const std::vector<uint8_t> &data, size_t &offset);
void parseDNSHeader(const std::vector<uint8_t> &packet, DNSHeader *header);

void parseDNSPacket(const std::vector<uint8_t> &packet, DNSHeader *header, DNSSections *sections);

void printSections(DNSHeader *header, DNSSections *sections, const std::vector<uint8_t> &packet);

void printQuestionSection(const std::vector<QuestionSection> &questions);

void printResourceRecord(const ResourceRecord &record, const std::vector<uint8_t> &packet);
ResourceRecord parseResourceRecord(const std::vector<uint8_t> &data, size_t &offset);

void printIPv6(const std::vector<uint8_t> &rData);

void printBytes(const unsigned char *data, int size);
void parseRawPacket(unsigned char *packet, ssize_t size, struct pcap_pkthdr captureHeader, inputArguments args, int offset);
void printVerboseDNS(const std::vector<uint8_t> &packet, DNSHeader *dnsHeader, const char *srcIP, const char *dstIP, DNSSections *sections, char *dateTime);
void printSimplifiedDNS(DNSHeader *dnsHeader, const char *srcIP, const char *dstIP, char *dateTime);
int isDNSPacket(const u_char *packet, int length);
char *getPacketTimestamp(struct pcap_pkthdr header, inputArguments args);