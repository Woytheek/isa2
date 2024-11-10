#include "../include/dns.h"

void printBytes(const unsigned char *data, int size)
{
    for (int i = 0; i < size; ++i)
    {
        // Print each byte in hex format with leading zeros
        printf("%02x", data[i]);
        if (i < size - 1)
        {
            printf(" "); // Print space between bytes
        }
    }
    printf("\n"); // End with a newline
}

int isDNSPacket(const u_char *packet, int length)
{
    // Check if the packet length is sufficient for Ethernet and IP headers
    if (length < 42)
    {             // 14 (Ethernet) + 20 (IP) + 8 (UDP) = 42
        return 0; // Not enough data for a DNS packet
    }

    for (int offset = 0; offset < length - 1; offset++)
    {
        if (packet[offset] == 0x45 && packet[offset + 1] == 0x00 && packet[offset - 1] == 0x00 && packet[offset - 2] == 0x08)
        {
            struct ip *ip_header = NULL;
            ip_header = (struct ip *)(packet + offset); // Nastavíme ukazatel na začátek IP hlavičky

            // Kontrola, zda je protokol UDP
            if (ip_header->ip_p != IPPROTO_UDP)
            {
                printf("NOT UDP %X\n", ip_header->ip_p);
                return 0; // Nejde o UDP paket
            }
            printf("UDP\n");

            // Posun na začátek UDP hlavičky
            struct udphdr *udp = (struct udphdr *)(packet + offset + (ip_header->ip_hl * 4));

            // Kontrola portů UDP (zdrojový nebo cílový port 53 pro DNS)
            if (ntohs(udp->uh_sport) == 53 || ntohs(udp->uh_dport) == 53)
            {
                printf("DNS\n");
                return offset; // TODO Jedná se o DNS paket
            }
            break;
        }

        // TODO TEST!!!!
        //  Check for IPv6 (new code)
        /*if (packet[offset] == 0x60 && packet[offset - 1] == 0xDD && packet[offset - 2] == 0x86)
        {                                                                     // Check if the first byte indicates IPv6
            struct ip6_hdr *ip6_header = (struct ip6_hdr *)(packet + offset); // Set pointer to IPv6 header

            // Check if the Next Header is UDP (17 for UDP)
            if (ip6_header->ip6_nxt != IPPROTO_UDP)
            {
                printf("NOT UDP (IPv6) %X\n", ip6_header->ip6_nxt);
                return 0; // Not UDP
            }
            printf("IPv6 UDP\n");

            // Move to the start of the UDP header
            struct udphdr *udp = (struct udphdr *)(packet + offset + sizeof(struct ip6_hdr));

            // Check for DNS (source or destination port 53)
            if (ntohs(udp->uh_sport) == 53 || ntohs(udp->uh_dport) == 53)
            {
                printf("DNS (IPv6)\n");
                return offset; // It's a DNS packet
            }
        }*/
    }
    return -1; // Nejde o DNS paket
}

void printSimplifiedDNS(DNSHeader *dnsHeader, const char *srcIP, const char *dstIP, char *dateTime)
{
    char qr = (dnsHeader->flags & 0x8000) ? 'R' : 'Q';
    int qdCount = dnsHeader->qdCount;
    int anCount = dnsHeader->anCount;
    int nsCount = dnsHeader->nsCount;
    int arCount = dnsHeader->arCount;

    printf("%s %s -> %s (%c %d/%d/%d/%d)\n", dateTime, srcIP, dstIP, qr, qdCount, anCount, nsCount, arCount);
}

void printVerboseDNS(DNSHeader *dnsHeader, const char *srcIP, const char *dstIP, DNSSections *sections, char *dateTime)
{
    printf("Timestamp: %s\n", dateTime);
    printf("SrcIP: %s\n", srcIP);
    printf("DstIP: %s\n", dstIP);
    printf("SrcPort: UDP/%d\n", PORT);
    printf("DstPort: UDP\n");

    printf("Identifier: 0x%X\n", dnsHeader->id);
    printf("Flags: QR=%d, OPCODE=%d, AA=%d, TC=%d, RD=%d, RA=%d, AD=%d, CD=%d, RCODE=%d\n",
           (dnsHeader->flags & 0x8000) >> 15,
           (dnsHeader->flags & 0x7800) >> 11,
           (dnsHeader->flags & 0x0400) >> 10,
           (dnsHeader->flags & 0x0200) >> 9,
           (dnsHeader->flags & 0x0100) >> 8,
           (dnsHeader->flags & 0x0080) >> 7,
           (dnsHeader->flags & 0x0020) >> 5,
           (dnsHeader->flags & 0x0010) >> 4,
           (dnsHeader->flags & 0x000F));

    printf("Flags: 0x%04X\n", dnsHeader->flags); // TODO: DELETE DEBUG PRINT

    if (dnsHeader->qdCount > 0)
    {
        printQuestionSection(sections->questions);
    }

    if (dnsHeader->anCount > 0)
    {
        printAnswerSection(sections->answers);
    }

    if (dnsHeader->nsCount > 0)
    {
        printAuthoritySection(sections->authorities);
    }

    if (dnsHeader->arCount > 0)
    {
        printAdditionalSection(sections->additionals);
    }

    printf("====================\n");
}

void parseRawPacket(unsigned char *buffer, ssize_t bufferSize, struct pcap_pkthdr header, inputArguments args, int offset)
{
    char dateTime[20];
    struct tm *timeinfo;

    if (args.p)
    {
        // Catched packet from PCAP file
        timeinfo = localtime(&header.ts.tv_sec);
    }
    else
    {
        // Catched live packet
        time_t rawtime;
        time(&rawtime);
        timeinfo = localtime(&rawtime);
    }

    strftime(dateTime, sizeof(dateTime), "%Y-%m-%d %H:%M:%S", timeinfo);
    parseDNSMessage(buffer, bufferSize, dateTime, args.v, offset);
    return;
}

void parseDNSMessage(unsigned char *packet, ssize_t size, char *dateTime, bool v, int offset)
{
    struct ip *ipHeader = (struct ip *)(packet + offset); // Skip Ethernet header

    // Extrakce zdrojové a cílové IP adresy
    char srcIP[INET_ADDRSTRLEN];
    char dstIP[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, &(ipHeader->ip_src), srcIP, INET_ADDRSTRLEN);
    inet_ntop(AF_INET, &(ipHeader->ip_dst), dstIP, INET_ADDRSTRLEN);

    // Přeskočíme Ethernet, IP a UDP headery k dosažení DNS sekce
    unsigned char *dnsPayload = packet + offset + (ipHeader->ip_hl * 4) + 8; // 8 bajtů pro délku UDP headeru

    // Výpočet velikosti DNS: celková velikost - Ethernet header - IP header - UDP header
    ssize_t dnsSize = size - (offset + (ipHeader->ip_hl * 4) + 8);

    DNSHeader *header = new DNSHeader();
    parseDNSHeader(std::vector<uint8_t>(dnsPayload, dnsPayload + dnsSize), header);

    DNSSections *sections = new DNSSections();
    parseDNSPacket(std::vector<uint8_t>(dnsPayload, dnsPayload + dnsSize), header, sections);

    if (v)
    {
        printVerboseDNS(header, srcIP, dstIP, sections, dateTime);
    }
    else
    {
        printSimplifiedDNS(header, srcIP, dstIP, dateTime);
    }
}

void parseDNSHeader(const std::vector<uint8_t> &packet, DNSHeader *header)
{
    // Parse Header
    int offset = 0;
    header->id = (packet[offset] << 8) | packet[offset + 1];
    header->flags = (packet[offset + 2] << 8) | packet[offset + 3];
    header->qdCount = (packet[offset + 4] << 8) | packet[offset + 5];
    header->anCount = (packet[offset + 6] << 8) | packet[offset + 7];
    header->nsCount = (packet[offset + 8] << 8) | packet[offset + 9];
    header->arCount = (packet[offset + 10] << 8) | packet[offset + 11];
}

void printQuestionSection(const std::vector<QuestionSection> &questions)
{
    printf("[Question Section]\n");
    for (const auto &question : questions)
    {
        printf("%s ", question.qName.c_str());
        // Print the question details using printf
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

        // Print the record type in human-readable format
        switch (question.qType)
        {
        case 1:
            printf("A\n"); // IPv4 address
            break;
        case 2:
            printf("NS\n"); // Name Server
            break;
        case 5:
            printf("CNAME\n"); // Canonical Name
            break;
        case 6:
            printf("SOA\n"); // Start of Authority
            break;
        case 15:
            printf("MX\n"); // Mail Exchange
            break;
        case 28:
            printf("AAAA\n"); // IPv6 address
            break;
        case 33:
            printf("SRV\n"); // Service record
            break;
        default:
            printf("%d\n", question.qType); // For any other type, print the numeric value
            break;
        }
    }
    printf("\n");
}

void printAnswerSection(const std::vector<ResourceRecord> &answers)
{
    printf("[Answer Section]\n");
    for (const auto &answer : answers)
    {
        // Print the name, TTL, IN, and record type
        printf("%s %u IN ", answer.name.c_str(), answer.ttl);

        // Print the type of record (A, AAAA, or the type number)
        if (answer.type == 1)
        {
            printf("A ");
        }
        else if (answer.type == 28)
        {
            printf("AAAA ");
        }
        else
        {
            printf("%u ", answer.type);
        }

        // Print IP address or other data depending on record type
        if (answer.type == 1)
        { // A record (IPv4)
            printf("%d.%d.%d.%d", (int)answer.rData[0], (int)answer.rData[1],
                   (int)answer.rData[2], (int)answer.rData[3]);
        }
        else if (answer.type == 28)
        { // AAAA record (IPv6)
            for (size_t i = 0; i < answer.rData.size(); i += 2)
            {
                // Print each pair of bytes as a 16-bit hexadecimal number
                printf("%x", (int)answer.rData[i] << 8 | (int)answer.rData[i + 1]);
                if (i + 2 < answer.rData.size())
                    printf(":");
            }
        }
        printf("\n");
    }
    printf("\n");
}

void printAuthoritySection(const std::vector<ResourceRecord> &authorities)
{
    printf("[Authority Section]\n");
    for (const auto &authority : authorities)
    {
        printf("%s %d IN NS %s\n", authority.name.c_str(), authority.ttl, authority.rData.data());
        // print all the authority attributes
        printf("Name: %s\n", authority.name.c_str());
        printf("Type: %d\n", authority.type);
        // print type in 0x format
        printf("Class: %d\n", authority.classCode);
        printf("TTL: %d\n", authority.ttl);
        printf("TTL: 0x%X\n", authority.ttl);
        printf("RD Length: %d\n", authority.rdLength);
    }
}

void printAdditionalSection(const std::vector<ResourceRecord> &additionals)
{
    // Print the "[Additional Section]" label
    printf("[Additional Section]\n");

    for (const auto &additional : additionals)
    {
        // Print the name, TTL, IN, and record type
        printf("%s %u IN ", additional.name.c_str(), additional.ttl);

        // Print the type of record (A or the type number)
        if (additional.type == 1)
        {
            printf("A ");
        }
        else
        {
            printf("%u ", additional.type);
        }

        // Print IP address (IPv4) if it's an A record
        if (additional.type == 1)
        { // A record (IPv4)
            printf("%d.%d.%d.%d", (int)additional.rData[0], (int)additional.rData[1],
                   (int)additional.rData[2], (int)additional.rData[3]);
        }

        // Newline after each additional record
        printf("\n");
    }

    // Newline at the end of the entire section
    printf("\n");
}

std::string readDomainName(const std::vector<uint8_t> &data, size_t &offset)
{
    std::string name;
    while (data[offset] != 0)
    {
        uint8_t len = data[offset++];
        if (len >= 192)
        { // Handle compression
            uint16_t pointer = ((len & 0x3F) << 8) | data[offset++];
            size_t tempOffset = pointer;
            name += readDomainName(data, tempOffset);
            break;
        }
        name += std::string(data.begin() + offset, data.begin() + offset + len) + ".";
        offset += len;
    }
    offset++; // Skip the null byte
    return name;
}

void parseDNSPacket(const std::vector<uint8_t> &packet, DNSHeader *header, DNSSections *sections)
{
    size_t offset = 0;
    offset += 12; // Skip header

    // Parse Question Section
    std::vector<QuestionSection> questions;
    for (int i = 0; i < header->qdCount; i++)
    {
        QuestionSection question;
        question.qName = readDomainName(packet, offset);
        question.qType = (packet[offset] << 8) | packet[offset + 1];
        question.qClass = (packet[offset + 2] << 8) | packet[offset + 3];
        offset += 4;
        questions.push_back(question);
    }

    // Parse Answer Section
    std::vector<ResourceRecord> answers;
    for (int i = 0; i < header->anCount; i++)
    {
        ResourceRecord answer;
        answer.name = readDomainName(packet, offset);
        answer.type = ntohs((packet[offset] << 8) | packet[offset + 1]);
        answer.classCode = ntohs((packet[offset + 2] << 8) | packet[offset + 3]);
        answer.ttl = (packet[offset + 4] << 24) | (packet[offset + 5] << 16) | (packet[offset + 6] << 8) | packet[offset + 7];
        answer.rdLength = (packet[offset + 8] << 8) | packet[offset + 9];
        offset += 10;
        answer.rData = std::vector<uint8_t>(packet.begin() + offset, packet.begin() + offset + answer.rdLength);
        offset += answer.rdLength;
        answers.push_back(answer);
    }

    // Parse Authority Section
    std::vector<ResourceRecord> authorities;
    for (int i = 0; i < header->nsCount; i++)
    {
        ResourceRecord authority;
        authority.name = readDomainName(packet, offset);
        authority.type = ntohs((packet[offset] << 8) | packet[offset + 1]);
        authority.classCode = ntohs((packet[offset + 2] << 8) | packet[offset + 3]);
        authority.ttl = ntohs((packet[offset + 4] << 24) | (packet[offset + 5] << 16) | (packet[offset + 6] << 8) | packet[offset + 7]);
        authority.rdLength = (packet[offset + 8] << 8) | packet[offset + 9];
        offset += 10;
        authority.rData = std::vector<uint8_t>(packet.begin() + offset, packet.begin() + offset + authority.rdLength);
        offset += authority.rdLength;
        authorities.push_back(authority);
    }

    // Parse Additional Section
    std::vector<ResourceRecord> additionals;
    for (int i = 0; i < header->arCount; i++)
    {
        ResourceRecord additional;
        additional.name = readDomainName(packet, offset);
        additional.type = (packet[offset] << 8) | packet[offset + 1];
        additional.classCode = (packet[offset + 2] << 8) | packet[offset + 3];
        additional.ttl = (packet[offset + 4] << 24) | (packet[offset + 5] << 16) | (packet[offset + 6] << 8) | packet[offset + 7];
        additional.rdLength = (packet[offset + 8] << 8) | packet[offset + 9];
        offset += 10;
        additional.rData = std::vector<uint8_t>(packet.begin() + offset, packet.begin() + offset + additional.rdLength);
        offset += additional.rdLength;
        additionals.push_back(additional);
    }

    if (questions.size() > 0)
    {
        sections->questions = questions;
    }
    if (answers.size() > 0)
    {
        sections->answers = answers;
    }
    if (authorities.size() > 0)
    {
        sections->authorities = authorities;
    }
    if (additionals.size() > 0)
    {
        sections->additionals = additionals;
    }
}
