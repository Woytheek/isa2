#pragma once

#include "include.h"
#include "argumentParser.h"
#include "translation.h"

void printBytes(const unsigned char *data, int size);
void printIPv6(const std::vector<uint8_t> &rData);

// Třída pro uchování informací o IP adrese
class IPInfo
{
public:
    char srcIP[INET_ADDRSTRLEN];
    char dstIP[INET_ADDRSTRLEN];
    char srcIP6[INET6_ADDRSTRLEN];
    char dstIP6[INET6_ADDRSTRLEN];
    int srcPort;
    int dstPort;
    bool isIPv6 = false;

    IPInfo() : srcPort(0), dstPort(0), isIPv6(false) {}
};

// Třída pro DNS hlavičku
class DNSHeader
{
public:
    uint16_t id;      // Transaction ID
    uint16_t flags;   // Flags and response codes
    uint16_t qdCount; // Number of questions
    uint16_t anCount; // Number of answers
    uint16_t nsCount; // Number of authority records
    uint16_t arCount; // Number of additional records

    DNSHeader() : id(0), flags(0), qdCount(0), anCount(0), nsCount(0), arCount(0) {}
};

// Třída pro DNS sekci dotazů
class QuestionSection
{
public:
    std::string qName;
    uint16_t qType;
    uint16_t qClass;

    QuestionSection() : qType(0), qClass(0) {}
};

// Třída pro DNS záznamy
class ResourceRecord
{
public:
    std::string name;
    uint16_t type;
    uint16_t classCode;
    uint32_t ttl;
    uint16_t rdLength;
    std::vector<uint8_t> rData;

    size_t rDataOffset;
    bool skip = false;

    ResourceRecord() : type(0), classCode(0), ttl(0), rdLength(0), rDataOffset(0), skip(false) {}
};

// Třída pro celé DNS sekce (dotazy, odpovědi, autoritativní záznamy atd.)
class DNSSections
{
public:
    std::vector<QuestionSection> questions;
    std::vector<ResourceRecord> answers;
    std::vector<ResourceRecord> authorities;
    std::vector<ResourceRecord> additionals;

    DNSSections() {}
};

// Třída pro zpracování DNS paketů a jejich výpisy
class DNSParser
{
private:
    inputArguments args; // Argumenty jako člen třídy

public:
    DNSParser(const inputArguments &arguments) : args(arguments) {} // Konstruktor s argumenty
    void parseRawPacket(unsigned char *packet, ssize_t size, struct pcap_pkthdr captureHeader, int offset);
    static int isDNSPacket(const u_char *packet, int length);

private:
    void parseDNSHeader(const std::vector<uint8_t> &packet, DNSHeader *header);
    void parseDNSPacket(const std::vector<uint8_t> &packet, DNSHeader *header, DNSSections *sections);
    ResourceRecord parseResourceRecord(const std::vector<uint8_t> &data, size_t &offset);

    char *getPacketTimestamp(struct pcap_pkthdr header);
    std::string readDomainName(const std::vector<uint8_t> &data, size_t &offset);

    void printVerboseDNS(const std::vector<uint8_t> &packet, DNSHeader *dnsHeader, IPInfo *ipInfo, DNSSections *sections, char *dateTime);
    void printSimplifiedDNS(DNSHeader *dnsHeader, IPInfo *ipInfo, char *dateTime);
    void printSections(DNSSections *sections, const std::vector<uint8_t> &packet);
    void printQuestionSection(const std::vector<QuestionSection> &questions);
    void printResourceRecord(const ResourceRecord &record, const std::vector<uint8_t> &packet);

    std::string ipv6ToString(const std::vector<uint8_t> &rData);
};
