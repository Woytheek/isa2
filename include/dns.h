#pragma once

#include "include.h"
#include "argumentParser.h"

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

void printQuestionSection(const std::vector<QuestionSection> &questions);
void printAnswerSection(const std::vector<ResourceRecord> &answers);
void printAuthoritySection(const std::vector<ResourceRecord> &authorities);
void printAdditionalSection(const std::vector<ResourceRecord> &additionals);

void printBytes(const unsigned char *data, int size);
void parseRawPacket(unsigned char *buffer, ssize_t bufferSize, struct pcap_pkthdr header, inputArguments args);
void parseDNSMessage(unsigned char *packet, ssize_t size, char *dateTime, bool v);
void printVerboseDNS(DNSHeader *dnsHeader, const char *srcIP, const char *dstIP, DNSSections *sections, char *dateTime);
void printSimplifiedDNS(DNSHeader *dnsHeader, const char *srcIP, const char *dstIP, char *dateTime);
int isDNSPacket(const u_char *packet, int length);
