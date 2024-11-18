/**
 * @file dns.cpp
 * @author Vojtěch Kuchař xkucha30
 * @brief Implements functionality for handling DNS packets, including parsing,
 *        extracting data, and printing details. Defines structures and classes
 *        for managing DNS headers, sections, and resource records.
 * @version 1.0
 * @date 2024-11-17
 *
 * @copyright Copyright (c) 2024
 *
 */

#include "../include/dns.h"

void DNSParser::parseRawPacket(unsigned char *packet, ssize_t size, struct pcap_pkthdr captureHeader, int offset)
{
    char *dateTime = getPacketTimestamp(captureHeader);

    struct ip6_hdr *ip6_header;
    struct ip *ipHeader;

    IPInfo ipInfo;

    unsigned char *dnsPayload;
    ssize_t dnsSize;

    // IPv4 packet processing
    if (packet[offset] == 0x45 && packet[offset + 1] == 0x00 && packet[offset - 1] == 0x00 && packet[offset - 2] == 0x08)
    {
        ipHeader = (struct ip *)(packet + offset);
        inet_ntop(AF_INET, &(ipHeader->ip_src), ipInfo.srcIP, INET_ADDRSTRLEN);
        inet_ntop(AF_INET, &(ipHeader->ip_dst), ipInfo.dstIP, INET_ADDRSTRLEN);

        // Skip IP header and UDP header
        dnsPayload = packet + offset + (ipHeader->ip_hl * 4) + 8;
        dnsSize = size - (offset + (ipHeader->ip_hl * 4) + 8);

        // Get the source and destination ports
        ipInfo.srcPort = ntohs(((struct udphdr *)(packet + offset + (ipHeader->ip_hl * 4)))->uh_sport);
        ipInfo.dstPort = ntohs(((struct udphdr *)(packet + offset + (ipHeader->ip_hl * 4)))->uh_dport);
    }

    // IPv6 packet processing
    if (packet[offset] == 0x60)
    {
        ipInfo.isIPv6 = true;
        ip6_header = (struct ip6_hdr *)(packet + offset);
        inet_ntop(AF_INET6, &(ip6_header->ip6_src), ipInfo.srcIP6, INET6_ADDRSTRLEN);
        inet_ntop(AF_INET6, &(ip6_header->ip6_dst), ipInfo.dstIP6, INET6_ADDRSTRLEN);

        // Skip IP header and UDP header
        dnsPayload = packet + offset + sizeof(struct ip6_hdr) + 8;
        dnsSize = size - (offset + sizeof(struct ip6_hdr) + 8);

        // Get the source and destination ports
        ipInfo.srcPort = ntohs(((struct udphdr *)(packet + offset + sizeof(struct ip6_hdr)))->uh_sport);
        ipInfo.dstPort = ntohs(((struct udphdr *)(packet + offset + sizeof(struct ip6_hdr)))->uh_dport);
    }

    // Create a unique pointer to DNSHeader for storing the parsed header
    auto header = std::make_unique<DNSHeader>();
    std::vector<uint8_t> dnsBody(dnsPayload, dnsPayload + dnsSize);

    // Parse the DNS header
    parseDNSHeader(dnsBody, header.get());

    // Create a unique pointer to DNSSections for storing the parsed sections
    auto sections = std::make_unique<DNSSections>();
    parseDNSPacket(dnsBody, header.get(), sections.get());

    handleDNSData(dnsBody, header.get(), &ipInfo, sections.get(), dateTime);

    delete[] dateTime;
    return;
}

void DNSParser::parseDNSHeader(const std::vector<uint8_t> &packet, DNSHeader *header)
{
    if (packet.size() < 12)
    {
        std::cerr << "Packet too short for parsing DNS header!" << std::endl;
        return;
    }

    int offset = 0;

    // Load the DNS header fields
    header->id = (packet[offset] << 8) | packet[offset + 1];
    header->flags = (packet[offset + 2] << 8) | packet[offset + 3];
    header->qdCount = (packet[offset + 4] << 8) | packet[offset + 5];
    header->anCount = (packet[offset + 6] << 8) | packet[offset + 7];
    header->nsCount = (packet[offset + 8] << 8) | packet[offset + 9];
    header->arCount = (packet[offset + 10] << 8) | packet[offset + 11];
}

void DNSParser::parseDNSPacket(const std::vector<uint8_t> &packet, DNSHeader *header, DNSSections *sections)
{
    size_t offset = 0;
    offset += 12;

    // Parse Question Section
    std::vector<QuestionSection> questions;
    for (int i = 0; i < header->qdCount; i++)
    {
        QuestionSection question;
        question.qName = readDomainName(packet, offset);
        offset += 1;
        question.qType = (packet[offset] << 8) | packet[offset + 1];
        question.qClass = (packet[offset + 2] << 8) | packet[offset + 3];
        offset += 4;
        questions.push_back(question);
    }

    // Parse Answer Section
    std::vector<ResourceRecord> answers;
    for (int i = 0; i < header->anCount; i++)
    {
        ResourceRecord answer = parseResourceRecord(packet, offset);
        if (!answer.skip)
        {
            answers.push_back(answer);
        }
    }

    // Parse Authority Section
    std::vector<ResourceRecord> authorities;
    for (int i = 0; i < header->nsCount; i++)
    {
        ResourceRecord authority = parseResourceRecord(packet, offset);
        if (!authority.skip)
        {
            authorities.push_back(authority);
        }
    }

    // Parse Additional Section
    std::vector<ResourceRecord> additionals;
    for (int i = 0; i < header->arCount; i++)
    {
        // Root domain (0x00) indicates the end of the additional section
        if (packet[offset] == 0)
        {
            header->arCount = i;
            break;
        }
        ResourceRecord additional = parseResourceRecord(packet, offset);
        if (!additional.skip)
        {
            additionals.push_back(additional);
        }
    }

    // Stores the parsed sections in the DNSSections object
    if (!questions.empty())
    {
        sections->questions = std::move(questions);
    }
    if (!answers.empty())
    {
        sections->answers = std::move(answers);
    }
    if (!authorities.empty())
    {
        sections->authorities = std::move(authorities);
    }
    if (!additionals.empty())
    {
        sections->additionals = std::move(additionals);
    }
}

void DNSParser::handleDNSData(const std::vector<uint8_t> &packet, DNSHeader *dnsHeader, IPInfo *ipInfo, DNSSections *sections, char *dateTime)
{
    // Print the DNS packet information based on verbosity settingss
    if (!args.v)
    {
        char qr = (dnsHeader->flags & 0x8000) ? 'R' : 'Q';

        // Counts of questions, answers, authorities, and additionals
        int qdCount = dnsHeader->qdCount;
        int anCount = dnsHeader->anCount;
        int nsCount = dnsHeader->nsCount;
        int arCount = dnsHeader->arCount;

        printf("%s %s -> %s (%c %d/%d/%d/%d)\n", dateTime, ipInfo->isIPv6 ? ipInfo->srcIP6 : ipInfo->srcIP, ipInfo->isIPv6 ? ipInfo->dstIP6 : ipInfo->dstIP, qr, qdCount, anCount, nsCount, arCount);
    }
    else
    {
        printf("Timestamp: %s\n", dateTime);
        printf("SrcIP: %s\n", ipInfo->isIPv6 ? ipInfo->srcIP6 : ipInfo->srcIP);
        printf("DstIP: %s\n", ipInfo->isIPv6 ? ipInfo->dstIP6 : ipInfo->dstIP);
        printf("SrcPort: UDP/%d\n", ipInfo->srcPort);
        printf("DstPort: UDP/%d\n", ipInfo->dstPort);
        printf("Identifier: 0x%X\n", dnsHeader->id);
        printf("Flags: QR=%d, OPCODE=%d, AA=%d, TC=%d, RD=%d, RA=%d, AD=%d, CD=%d, RCODE=%d\n",
               (dnsHeader->flags & 0x8000) >> 15, // QR
               (dnsHeader->flags & 0x7800) >> 11, // OPCODE
               (dnsHeader->flags & 0x0400) >> 10, // AA
               (dnsHeader->flags & 0x0200) >> 9,  // TC
               (dnsHeader->flags & 0x0100) >> 8,  // RD
               (dnsHeader->flags & 0x0080) >> 7,  // RA
               (dnsHeader->flags & 0x0020) >> 5,  // AD
               (dnsHeader->flags & 0x0010) >> 4,  // CD
               (dnsHeader->flags & 0x000F));      // RCODE
    }

    // Print the DNS sections
    printSections(sections, packet);

    if (args.v)
    {
        printf("====================\n");
    }
}

std::string DNSParser::readDomainName(const std::vector<uint8_t> &data, size_t &offset)
{
    std::string name;

    // Read the domain name from the DNS data
    while (data[offset] != 0)
    {
        uint8_t len = data[offset++];
        // If the two most significant bits are set, it's a pointer (compression of domain name)
        if (len >= 192)
        {
            uint16_t pointer = ((len & 0x3F) << 8) | data[offset++]; // Get the pointer value of the compressed domain name
            size_t tempOffset = pointer;
            name += readDomainName(data, tempOffset); // Recursively read the compressed domain name
            break;
        }
        name += std::string(data.begin() + offset, data.begin() + offset + len) + ".";
        offset += len;
    }

    return name;
}

ResourceRecord DNSParser::parseResourceRecord(const std::vector<uint8_t> &data, size_t &offset)
{
    // Create a ResourceRecord object to store the parsed record
    ResourceRecord record;
    record.name = readDomainName(data, offset);
    record.type = (data[offset] << 8) | data[offset + 1];

    // Skip records that are not to be supported
    if (record.type != 1 && record.type != 2 && record.type != 5 && record.type != 6 && record.type != 15 && record.type != 28 && record.type != 33)
    {
        record.skip = true;
    }

    record.classCode = (data[offset + 2] << 8) | data[offset + 3];
    record.ttl = (data[offset + 4] << 24) | (data[offset + 5] << 16) | (data[offset + 6] << 8) | data[offset + 7];
    record.rdLength = (data[offset + 8] << 8) | data[offset + 9];
    offset += 10;

    record.rData = std::vector<uint8_t>(data.begin() + offset, data.begin() + offset + record.rdLength);
    record.rDataOffset = offset;

    offset += record.rdLength;

    return record;
}

void DNSParser::printSections(DNSSections *sections, const std::vector<uint8_t> &packet)
{
    // Print the DNS question and sections if they are any detected in verbose or simplified format
    if (!sections->questions.empty())
    {
        printQuestionSection(sections->questions);
    }

    if (!sections->answers.empty())
    {
        if (args.v)
        {
            printf("\n[Answer Section]\n");
        }
        for (const auto &answer : sections->answers)
        {
            printResourceRecord(answer, packet);
        }
    }

    if (!sections->authorities.empty())
    {
        if (args.v)
        {
            printf("\n[Authority Section]\n");
        }
        for (const auto &authority : sections->authorities)
        {
            printResourceRecord(authority, packet);
        }
    }

    if (!sections->additionals.empty())
    {
        if (args.v)
        {
            printf("\n[Additional Section]\n");
        }
        for (const auto &additional : sections->additionals)
        {
            printResourceRecord(additional, packet);
        }
    }
}

void DNSParser::printQuestionSection(const std::vector<QuestionSection> &questions)
{
    if (args.v)
    {
        printf("\n[Question Section]\n");
        for (const auto &question : questions)
        {
            printf("%s ", question.qName.c_str());

            switch (question.qClass)
            {
            default:
            case 1:
                printf("IN ");
                break;
            case 2:
                printf("CS ");
                break;
            case 3:
                printf("CH ");
                break;
            case 4:
                printf("HS ");
                break;
            }

            // This implementation supports all the basic types of DNS queries, complies with RFC 1035 standards + AAAA and SRV records. Other types are printed as numbers.
            switch (question.qType)
            {
            case 1:
                printf("A\n"); // IPv4 address
                break;
            case 2:
                printf("NS\n"); // Name server
                break;
            case 5:
                printf("CNAME\n"); // Canonical name for an alias
                break;
            case 6:
                printf("SOA\n"); // Start of authority
                break;
            case 15:
                printf("MX\n"); // Mail exchange
                break;
            case 28:
                printf("AAAA\n"); // IPv6 address
                break;
            case 33:
                printf("SRV\n"); // Service record
                break;
            case 3:
                printf("MD\n"); // Mail destination (Obsolete - use MX)
                break;
            case 4:
                printf("MF\n"); // Mail forwarder (Obsolete - use MX)
                break;
            case 7:
                printf("MB\n"); // Mailbox domain name (Experimental)
                break;
            case 8:
                printf("MG\n"); // Mail group member (Experimental)
                break;
            case 9:
                printf("MR\n"); // Mail rename domain name (Experimental)
                break;
            case 10:
                printf("NULL\n"); // Null RR (Experimental)
                break;
            case 11:
                printf("WKS\n"); // Well-known service description
                break;
            case 12:
                printf("PTR\n"); // Domain name pointer
                break;
            case 13:
                printf("HINFO\n"); // Host information
                break;
            case 14:
                printf("MINFO\n"); // Mailbox or mail list information
                break;
            case 16:
                printf("TXT\n"); // Text strings
                break;
            default:
                printf("%d\n", question.qType); // If the type is unknown, print the number
                break;
            }
        }
    }
}

void DNSParser::printResourceRecord(const ResourceRecord &record, const std::vector<uint8_t> &packet)
{
    if (record.type != 1 && record.type != 2 && record.type != 5 && record.type != 6 && record.type != 15 && record.type != 28 && record.type != 33)
    {
        return; // Skip unsupported record types
    }

    std::string recordClass;
    switch (record.classCode)
    {
    case 1:
        recordClass = "IN";
        break;
    case 2:
        recordClass = "CS";
        break;
    case 3:
        recordClass = "CH";
        break;
    case 4:
        recordClass = "HS";
        break;
    default:
        break;
    }

    // Variables for storing and printing parsed data
    size_t tempOffset = record.rDataOffset;
    std::string dname, ip, exchange, cname, mname, rname, target;
    uint16_t priority, weight, port;
    uint32_t serial, refresh, retry, expire, minimum;

    // Translation object
    Translation tran(args.domainsFile, args.translationsFile);

    // Switch based on the record type
    switch (record.type)
    {
    case 1: // A (IPv4 Address)
    {
        ip = std::to_string((int)record.rData[0]) + "." + std::to_string((int)record.rData[1]) + "." + std::to_string((int)record.rData[2]) + "." + std::to_string((int)record.rData[3]);
        if (args.v)
        {
            printf("%s %d %s A %s\n", record.name.c_str(), record.ttl, recordClass.c_str(), ip.c_str());
        }
        tran.loadTranslation(record.name, ip);
        break;
    }

    case 2: // NS (Name Server)
    {
        dname = readDomainName(packet, tempOffset);
        if (args.v)
        {
            printf("%s %d %s NS %s\n", record.name.c_str(), record.ttl, recordClass.c_str(), dname.c_str());
        }
        tran.loadTranslation(record.name);
        tran.loadTranslation(dname);
        break;
    }

    case 5: // CNAME (Canonical Name)
    {
        cname = readDomainName(packet, tempOffset);
        if (args.v)
        {
            printf("%s %d %s CNAME %s\n", record.name.c_str(), record.ttl, recordClass.c_str(), cname.c_str());
        }
        tran.loadTranslation(record.name);
        tran.loadTranslation(cname);
        break;
    }

    case 6: // SOA (Start of Authority)
    {
        mname = readDomainName(packet, tempOffset);
        rname = readDomainName(packet, tempOffset);

        // Parse 32-bit SOA fields
        serial = ntohl(*(uint32_t *)(packet.data() + tempOffset));
        refresh = ntohl(*(uint32_t *)(packet.data() + tempOffset + 4));
        retry = ntohl(*(uint32_t *)(packet.data() + tempOffset + 8));
        expire = ntohl(*(uint32_t *)(packet.data() + tempOffset + 12));
        minimum = ntohl(*(uint32_t *)(packet.data() + tempOffset + 16));
        tempOffset += 20;

        if (args.v)
        {
            printf("%s %d %s SOA %s %s %u %u %u %u %u\n", record.name.c_str(), record.ttl, recordClass.c_str(), mname.c_str(), rname.c_str(), serial, refresh, retry, expire, minimum);
        }
        // Translation load
        tran.loadTranslation(record.name);
        tran.loadTranslation(mname);
        break;
    }

    case 15: // MX (Mail Exchange)
    {
        size_t MXtempOffset = tempOffset + 2;
        exchange = readDomainName(packet, MXtempOffset);
        uint16_t preference = (record.rData[0] << 8) | record.rData[1];
        if (args.v)
        {
            printf("%s %d %s MX %d %s\n", record.name.c_str(), record.ttl, recordClass.c_str(), preference, exchange.c_str());
        }
        tran.loadTranslation(record.name);
        tran.loadTranslation(exchange);
        break;
    }

    case 28: // AAAA (IPv6 Address)
    {
        std::string ipv6 = ipv6ToString(record.rData);
        if (args.v)
        {
            printf("%s %d %s AAAA %s\n", record.name.c_str(), record.ttl, recordClass.c_str(), ipv6.c_str());
        }
        tran.loadTranslation(record.name, ipv6);
        break;
    }

    case 33: // SRV (Service Record)
    {
        priority = (record.rData[0] << 8) | record.rData[1];
        weight = (record.rData[2] << 8) | record.rData[3];
        port = (record.rData[4] << 8) | record.rData[5];
        tempOffset = record.rDataOffset + 6;
        target = readDomainName(packet, tempOffset);
        if (args.v)
        {
            printf("%s %d %s SRV %d %d %d %s\n", record.name.c_str(), record.ttl, recordClass.c_str(), priority, weight, port, target.c_str());
        }
        tran.loadTranslation(target);
        break;
    }
    default:
        break; // Unknown record type (should not happen)
    }

    // Write translations and domains into files if requested
    if (args.t)
    {
        tran.printTranslations();
    }

    if (args.d)
    {
        tran.printDomains();
    }
}

void printBytes(const unsigned char *data, int size)
{
    for (int i = 0; i < size; ++i)
    {
        printf("%02x", data[i]);
        if (i < size - 1)
        {
            printf(" ");
        }
    }
    printf("\n");
}

std::string DNSParser::ipv6ToString(const std::vector<uint8_t> &rData)
{
    std::string ipv6;

    uint16_t blocks[8];
    for (size_t i = 0; i < 8; ++i)
    {
        blocks[i] = (rData[2 * i] << 8) | rData[2 * i + 1];
    }

    // Find the longest sequence of zeros for compression (::)
    int max_zeros = 0, best_zero_start = -1;
    for (int i = 0; i < 8; ++i)
    {
        if (blocks[i] == 0)
        {
            int j = i;
            while (j < 8 && blocks[j] == 0)
                ++j;
            int zero_count = j - i;
            if (zero_count > max_zeros)
            {
                max_zeros = zero_count;
                best_zero_start = i;
            }
            i = j;
        }
    }

    // Construct the IPv6 address string with the compressed zeros
    for (int i = 0; i < 8; ++i)
    {
        if (i == best_zero_start)
        {
            ipv6 += "::";
            i += max_zeros - 1;
            continue;
        }
        if (i > 0 && i != best_zero_start + max_zeros)
        {
            ipv6 += ":";
        }
        ipv6 += std::to_string(blocks[i]);
    }
    return ipv6;
}

int DNSParser::isDNSPacket(const u_char *packet, int length)
{
    if (length < 42) // Must be at least 42 = 14 (Ethernet) + 20 (IP) + 8 (UDP)
    {
        return -1;
    }
    for (int offset = 0; offset < length - 1; offset++)
    {
        // ipv4 packet check
        if (packet[offset] == 0x45 && packet[offset + 1] == 0x00 && packet[offset - 1] == 0x00 && packet[offset - 2] == 0x08)
        {
            IPInfo ipInfo;
            struct ip *ip_header = (struct ip *)(packet + offset);

            inet_ntop(AF_INET, &(ip_header->ip_src), ipInfo.srcIP, INET_ADDRSTRLEN);
            inet_ntop(AF_INET, &(ip_header->ip_dst), ipInfo.dstIP, INET_ADDRSTRLEN);
            ipInfo.srcPort = 0;
            ipInfo.dstPort = 0;

            // Check if the Next Header is UDP (17 for UDP)
            if (ip_header->ip_p != IPPROTO_UDP)
            {
                return -1;
            }

            struct udphdr *udp = (struct udphdr *)(packet + offset + (ip_header->ip_hl * 4));

            // Check UDP ports (source or destination port 53 for DNS)
            if (ntohs(udp->uh_sport) == 53 || ntohs(udp->uh_dport) == 53)
            {
                return offset;
            }
        }

        // ipv6 packet check (similar to ipv4)
        if (packet[offset] == 0x60 && packet[offset - 1] == 0xDD && packet[offset - 2] == 0x86)
        {
            IPInfo ipInfo;
            struct ip6_hdr *ip6_header = (struct ip6_hdr *)(packet + offset);

            inet_ntop(AF_INET6, &(ip6_header->ip6_src), ipInfo.srcIP6, INET6_ADDRSTRLEN);
            inet_ntop(AF_INET6, &(ip6_header->ip6_dst), ipInfo.dstIP6, INET6_ADDRSTRLEN);
            ipInfo.isIPv6 = true;

            if (ip6_header->ip6_nxt != IPPROTO_UDP)
            {
                return -1;
            }

            struct udphdr *udp = (struct udphdr *)(packet + offset + sizeof(struct ip6_hdr));

            if (ntohs(udp->uh_sport) == 53 || ntohs(udp->uh_dport) == 53)
            {
                return offset;
            }
        }
    }

    return -1;
}

char *DNSParser::getPacketTimestamp(struct pcap_pkthdr header)
{
    char *dateTime = new char[20];
    struct tm *timeinfo;

    if (args.p)
    {
        timeinfo = localtime(&header.ts.tv_sec); // Convert the PCAP timestamp to local time
    }
    else
    {
        // Get the current time if the packet is captured live
        time_t rawtime;
        time(&rawtime);
        timeinfo = localtime(&rawtime);
    }

    // Load the formatted time into the dateTime string
    strftime(dateTime, 20, "%Y-%m-%d %H:%M:%S", timeinfo);

    return dateTime;
}
