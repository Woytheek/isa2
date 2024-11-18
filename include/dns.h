/**
 * @file dns.h
 * @author Vojtěch Kuchař xkucha30
 * @brief Defines functionality for handling DNS packets, including parsing,
 *        extracting data, and printing details. Defines structures and classes
 *        for managing DNS headers, sections, and resource records.
 * @version 1.0
 * @date 2024-11-17
 *
 * @copyright Copyright (c) 2024
 *
 */

#pragma once

#include "include.h"
#include "argumentParser.h"
#include "translation.h"

/**
 * @brief Prints the raw bytes of a given data buffer in hexadecimal format.
 *
 * This function outputs the bytes of a given buffer in hexadecimal format, with each byte printed as a two-digit
 * hexadecimal value. Bytes are separated by a space for readability.
 *
 * @param data A pointer to the data buffer to be printed.
 * @param size The size of the data buffer in bytes.
 */
void printBytes(const unsigned char *data, int size);

/**
 * @brief Represents IP information (both IPv4 and IPv6).
 *
 * This class holds the source and destination IP addresses (both IPv4 and IPv6), as well as the source
 * and destination port numbers. It also keeps track of whether the packet is IPv6.
 */
class IPInfo
{
public:
    char srcIP[INET_ADDRSTRLEN];   // Source IPv4 address in string format
    char dstIP[INET_ADDRSTRLEN];   // Destination IPv4 address in string format
    char srcIP6[INET6_ADDRSTRLEN]; // Source IPv6 address in string format
    char dstIP6[INET6_ADDRSTRLEN]; // Destination IPv6 address in string format
    int srcPort;                   // Source port number (for UDP or TCP)
    int dstPort;                   // Destination port number (for UDP or TCP)
    bool isIPv6 = false;           // Flag indicating whether the IP is IPv6

    /**
     * @brief Default constructor initializing ports to 0 and isIPv6 flag to false.
     */
    IPInfo() : srcPort(0), dstPort(0), isIPv6(false) {}
};

/**
 * @brief Represents the DNS header.
 *
 * This class contains the DNS transaction ID, flags, and the counts for the sections in the DNS packet
 * (questions, answers, authorities, and additional records).
 */
class DNSHeader
{
public:
    uint16_t id;      // Transaction ID
    uint16_t flags;   // Flags and response codes
    uint16_t qdCount; // Number of questions
    uint16_t anCount; // Number of answers
    uint16_t nsCount; // Number of authority records
    uint16_t arCount; // Number of additional records

    /**
     * @brief Default constructor initializing all values to 0.
     */
    DNSHeader() : id(0), flags(0), qdCount(0), anCount(0), nsCount(0), arCount(0) {}
};

/**
 * @brief Represents a single DNS query question in the question section.
 *
 * This class stores the query name (`qName`), query type (`qType`), and query class (`qClass`).
 */
class QuestionSection
{
public:
    std::string qName; // The domain name being queried
    uint16_t qType;    // Type of the DNS query (e.g., A, AAAA, MX, etc.)
    uint16_t qClass;   // Class of the DNS query (e.g., IN for Internet)

    /**
     * @brief Default constructor initializing query type and class to 0.
     */
    QuestionSection() : qType(0), qClass(0) {}
};

/**
 * @brief Represents a DNS resource record.
 *
 * This class holds the details of a DNS record, including the name, type, class, TTL, and resource data.
 * It also includes an offset (`rDataOffset`) to manage the position of resource data within the DNS packet.
 */
class ResourceRecord
{
public:
    std::string name;           // The name of the record (e.g., domain name)
    uint16_t type;              // Type of the record (e.g., A, AAAA, NS, MX)
    uint16_t classCode;         // Class of the record (e.g., IN for Internet)
    uint32_t ttl;               // Time to live for the record
    uint16_t rdLength;          // Length of the resource data
    std::vector<uint8_t> rData; // The resource data associated with the record (e.g., IP address)

    size_t rDataOffset; // Offset in the packet where the resource data begins
    bool skip = false;  // Flag to indicate if the record should be skipped

    /**
     * @brief Default constructor initializing fields to default values.
     */
    ResourceRecord() : type(0), classCode(0), ttl(0), rdLength(0), rDataOffset(0), skip(false) {}
};

/**
 * @brief Represents the sections of a DNS packet: questions, answers, authorities, and additionals.
 *
 * This class holds the DNS QuestionSection, answer ResourceRecords, authority ResourceRecords, and additional
 * ResourceRecords. These sections are populated based on the content of the DNS packet.
 */
class DNSSections
{
public:
    std::vector<QuestionSection> questions;  // The list of questions in the DNS query
    std::vector<ResourceRecord> answers;     // The list of answers in the DNS response
    std::vector<ResourceRecord> authorities; // The list of authority records in the DNS response
    std::vector<ResourceRecord> additionals; // The list of additional records in the DNS response

    /**
     * @brief Default constructor for DNSSections.
     */
    DNSSections() {}
};

/**
 * @brief DNS packet parser that processes and extracts DNS information from raw packet data.
 *
 * This class handles parsing DNS packets, extracting details like DNS headers, questions, answers, and more.
 * It also includes utility functions to handle IP address formatting and DNS query validation.
 */
class DNSParser
{
private:
    inputArguments args; // The arguments used for controlling the parsing behavior

public:
    DNSParser(const inputArguments &arguments) : args(arguments) {}

    /**
     * @brief Parse the raw DNS packet. This method is the main entry point for parsing a raw DNS packet.
     * It extracts DNS header, sections (questions, answers, authorities, additional records),
     * and then processes the DNS data.
     *
     * @param packet The raw DNS packet.
     * @param size The size of the packet.
     * @param captureHeader The capture header containing timestamp information.
     * @param offset The offset to start parsing from.
     */
    void parseRawPacket(unsigned char *packet, ssize_t size, struct pcap_pkthdr captureHeader, int offset);

    /**
     * @brief Check if the packet is a DNS packet.
     *
     * This method determines if a given packet is a valid DNS packet based on its content.
     *
     * @param packet The raw packet data.
     * @param length The length of the packet.
     *
     * @return The offset to start parsing from if it is a DNS packet, otherwise -1.
     */
    static int isDNSPacket(const u_char *packet, int length);

private:
    /**
     * @brief Parse the DNS header from the packet.
     *
     * This method extracts the DNS header fields, including the transaction ID,
     * flags, and record counts.
     *
     * @param packet The raw packet data.
     * @param header A pointer to the DNSHeader structure to store the parsed header.
     */
    void parseDNSHeader(const std::vector<uint8_t> &packet, DNSHeader *header);

    /**
     * @brief Parse the DNS sections (questions, answers, authorities, additional records).
     *        This method parses the DNS packet and fills the DNSSections structure with
     *        the parsed data.
     *
     * @param packet The raw DNS packet data.
     * @param header The DNS header structure.
     * @param sections The DNSSections structure to store the parsed sections.
     */
    void parseDNSPacket(const std::vector<uint8_t> &packet, DNSHeader *header, DNSSections *sections);

    /**
     * @brief Parses a DNS resource record from the provided data, including the domain name, type, class code, TTL, and data length.
     *        Skips the unsuported records.
     *
     * @param data A vector containing the DNS packet data.
     * @param offset A reference to the offset in the data vector, which is updated as the resource record is parsed.
     * @return A ResourceRecord object containing the parsed record's details.
     */
    ResourceRecord parseResourceRecord(const std::vector<uint8_t> &data, size_t &offset);

    /**
     * @brief Retrieves the timestamp of a captured packet.
     *        This function returns the timestamp of a captured packet in a human-readable format (YYYY-MM-DD HH:MM:SS).
     *        It either uses the timestamp embedded in the packet header (if the packet is from a capture file) or
     *        uses the current time (if the packet is captured live).
     *
     * @param header The header of the packet (from `pcap_pkthdr`).
     * @return A dynamically allocated string containing the formatted timestamp.
     */
    char *getPacketTimestamp(struct pcap_pkthdr header);

    /**
     * @brief Reads a domain name from the given DNS data, handling domain name compression as defined by the DNS protocol.
     *        It processes segments of the domain name and returns the full domain name as a string.
     *
     * @param data A vector containing the DNS packet data.
     * @param offset A reference to the offset in the data vector, which is updated as the domain name is read.
     * @return A string representing the fully parsed domain name.
     */
    std::string readDomainName(const std::vector<uint8_t> &data, size_t &offset);

    /**
     * @brief Handles DNS data by printing relevant information based on verbosity settings.
     *        This includes DNS header information, IP details, and sections of the DNS packet.
     *
     * @param packet A vector containing the raw DNS packet data.
     * @param dnsHeader A pointer to the DNSHeader object, holding parsed DNS header information.
     * @param ipInfo A pointer to the IPInfo object, holding parsed IP header information.
     * @param sections A pointer to the DNSSections object, holding parsed DNS packet sections (questions, answers, etc.).
     * @param dateTime A string representing the timestamp of the packet capture.
     */
    void handleDNSData(const std::vector<uint8_t> &packet, DNSHeader *dnsHeader, IPInfo *ipInfo, DNSSections *sections, char *dateTime);

    /**
     * @brief Prints the DNS sections (Question, Answer, Authority, Additional) based on the data contained in DNSSections.
     *        This function also takes into account the verbosity flag to determine the level of detail in the output.
     *
     * @param sections A pointer to the DNSSections object, holding the parsed sections of the DNS packet.
     * @param packet A vector containing the raw DNS packet data, used for further processing and printing.
     */
    void printSections(DNSSections *sections, const std::vector<uint8_t> &packet);

    /**
     * @brief Prints the DNS Question Section.
     *        This function outputs the DNS query name (`qName`), class (`qClass`), and type (`qType`) for each
     *        question in the provided vector. It prints the information only if verbosity (`args.v`) is enabled.
     *
     * @param questions A vector of `QuestionSection` objects representing the DNS queries.
     *
     */
    void printQuestionSection(const std::vector<QuestionSection> &questions);

    /**
     * @brief Prints a resource record from the DNS packet.
     *        A resource record (RR) represents various types of information in a DNS response. This function
     *        prints out the resource record details including the record's name, class, type, TTL, and data (e.g., IP addresses,
     *        domain names). It supports different record types such as A (IPv4 address), AAAA (IPv6 address), NS (Name Server),
     *        CNAME (Canonical Name), MX (Mail Exchange), and others.
     *        In verbose mode (`args.v`), the function outputs the details of the record. It also loads translation information
     *        for the domain names and data in the record, if available.
     *
     * @param record A `ResourceRecord` structure containing the parsed data of the resource record.
     * @param packet A vector of bytes representing the DNS packet.
     */
    void printResourceRecord(const ResourceRecord &record, const std::vector<uint8_t> &packet);

    /**
     * @brief Converts a raw IPv6 address (16 bytes) into its string representation.
     *        This function takes a 16-byte array representing an IPv6 address and converts it into its
     *        human-readable form, including support for "::".
     *
     * @param rData A vector of 16 bytes representing the IPv6 address.
     * @return A string representing the IPv6 address, or an error message if the input is invalid.
     */
    std::string ipv6ToString(const std::vector<uint8_t> &rData);
};
