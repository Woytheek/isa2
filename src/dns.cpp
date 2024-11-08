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

    // Pointer to IP header
    struct ip *ip = (struct ip *)(packet + 14); // Skip Ethernet header
    // Pointer to UDP header
    struct udphdr *udp = (struct udphdr *)(packet + 14 + (ip->ip_hl * 4)); // Skip Ethernet and IP headers

    // Check if the protocol is UDP (17)
    if (ip->ip_p != IPPROTO_UDP)
    {
        return 0; // Not a UDP packet
    }

    // Check if the source or destination port is 53 (DNS)
    if (ntohs(udp->uh_sport) == 53 || ntohs(udp->uh_dport) == 53)
    {
        return 1; // It is a DNS packet
    }

    return 0; // Not a DNS packet
}

void printSimplifiedDNS(DNSHeader *dnsHeader, const char *srcIP, const char *dstIP, char *dateTime)
{
    char qr = (ntohs(dnsHeader->flags) & 0x8000) ? 'R' : 'Q';
    int qdCount = ntohs(dnsHeader->qdCount);
    int anCount = ntohs(dnsHeader->anCount);
    int nsCount = ntohs(dnsHeader->nsCount);
    int arCount = ntohs(dnsHeader->arCount);

    printf("%s %s -> %s (%c %d/%d/%d/%d)\n", dateTime, srcIP, dstIP, qr, qdCount, anCount, nsCount, arCount);
}

void printVerboseDNS(DNSHeader *dnsHeader, const char *srcIP, const char *dstIP, ssize_t size, unsigned char *buffer, char *dateTime)
{
    printf("Timestamp: %s\n", dateTime);
    printf("SrcIP: %s\n", srcIP);
    printf("DstIP: %s\n", dstIP);
    printf("SrcPort: UDP/%d\n", PORT);
    printf("DstPort: UDP\n");

    printf("Identifier: 0x%X\n", ntohs(dnsHeader->id));
    printf("Flags: QR=%d, OPCODE=%d, AA=%d, TC=%d, RD=%d, RA=%d, AD=%d, CD=%d, RCODE=%d\n",
           (ntohs(dnsHeader->flags) & 0x8000) >> 15,
           (ntohs(dnsHeader->flags) & 0x7800) >> 11,
           (ntohs(dnsHeader->flags) & 0x0400) >> 10,
           (ntohs(dnsHeader->flags) & 0x0200) >> 9,
           (ntohs(dnsHeader->flags) & 0x0100) >> 8,
           (ntohs(dnsHeader->flags) & 0x0080) >> 7,
           (ntohs(dnsHeader->flags) & 0x0020) >> 5,
           (ntohs(dnsHeader->flags) & 0x0010) >> 4,
           (ntohs(dnsHeader->flags) & 0x000F));

    if (ntohs(dnsHeader->qdCount) > 0)
    {
        printf("\n[Question Section]\n");
        for (int i = sizeof(DNSHeader); i < size; ++i)
        {
            printf("%c", (unsigned char)buffer[i]);
        }
        printf("\n");
    }

    if (ntohs(dnsHeader->anCount) > 0)
    {
        printf("\n[Answer Section]\n");

        printf("\n");
    }

    if (ntohs(dnsHeader->nsCount) > 0)
    {
        printf("\n[Authority Section]\n");

        printf("\n");
    }

    if (ntohs(dnsHeader->arCount) > 0)
    {
        printf("\n[Additional Section]\n");

        printf("\n");
    }

    printf("====================\n");
}

void parseRawPacket(unsigned char *buffer, ssize_t bufferSize, struct pcap_pkthdr header, inputArguments args)
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
    parseDNSMessage(buffer, bufferSize, dateTime, args.v);
    return;
}

void parseDNSMessage(unsigned char *packet, ssize_t size, char *dateTime, bool v)
{
    (void)dateTime;
    (void)v;

    // Předpokládáme Ethernetový header (14 bajtů), extrahujeme IP header
    struct ip *ipHeader = (struct ip *)(packet + 14); // Skip Ethernet header

    // Extrakce zdrojové a cílové IP adresy
    char srcIP[INET_ADDRSTRLEN];
    char dstIP[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, &(ipHeader->ip_src), srcIP, INET_ADDRSTRLEN);
    inet_ntop(AF_INET, &(ipHeader->ip_dst), dstIP, INET_ADDRSTRLEN);

    // Přeskočíme Ethernet, IP a UDP headery k dosažení DNS sekce
    unsigned char *dnsPayload = packet + 14 + (ipHeader->ip_hl * 4) + 8; // 8 bajtů pro délku UDP headeru

    // Výpočet velikosti DNS: celková velikost - Ethernet header - IP header - UDP header
    ssize_t dnsSize = size - (14 + (ipHeader->ip_hl * 4) + 8);

    parseDNSPacket(std::vector<uint8_t>(dnsPayload, dnsPayload + dnsSize));
    /*// Zajištění, že velikost DNS paketu je validní
    if (dnsSize < (ssize_t)sizeof(DNSHeader))
    {
        printf("Invalid DNS packet after IP header\n");
        return;
    }

    // Ukazatel na DNS header
    DNSHeader *dnsHeader = (DNSHeader *)dnsPayload;

    // Zkontrolujeme, zda je zapnutý podrobný režim
    if (v)
    {
        // Předáme &header jako ukazatel na strukturu pcap_pkthdr
        printVerboseDNS(dnsHeader, srcIP, dstIP, dnsSize, dnsPayload, dateTime);
    }
    else
    {
        printSimplifiedDNS(dnsHeader, srcIP, dstIP, dateTime);
    }*/
}

////////////////////////////////////////////////////////////////////////////////////

// Function to print the Question Section


void printQuestionSection(const std::vector<QuestionSection>& questions) {
    printf("[Question Section]\n");
    for (const auto& question : questions) {
        // Print the question details using printf
        printf("%s IN ", question.qName.c_str());
        
        // Print the record type in human-readable format
        switch (question.qType) {
            case 1:
                printf("A\n");      // IPv4 address
                break;
            case 28:
                printf("AAAA\n");   // IPv6 address
                break;
            case 2:
                printf("NS\n");     // Name Server
                break;
            case 15:
                printf("MX\n");     // Mail Exchange
                break;
            case 6:
                printf("SOA\n");    // Start of Authority
                break;
            case 5:
                printf("CNAME\n");  // Canonical Name
                break;
            case 33:
                printf("SRV\n");    // Service record
                break;
            default:
                printf("%d\n", question.qType);  // For any other type, print the numeric value
                break;
        }
    }
    printf("\n");
}


// Function to print the Answer Section
void printAnswerSection(const std::vector<ResourceRecord> &answers)
{
    std::cout << "[Answer Section]" << std::endl;
    for (const auto &answer : answers)
    {
        std::cout << answer.name << ". "
                  << answer.ttl << " "
                  << "IN "
                  << (answer.type == 1 ? "A" : answer.type == 28 ? "AAAA"
                                                                 : std::to_string(answer.type))
                  << " ";
        // Print IP address or other data depending on record type
        if (answer.type == 1)
        { // A record (IPv4)
            std::cout << (int)answer.rData[0] << "." << (int)answer.rData[1] << "."
                      << (int)answer.rData[2] << "." << (int)answer.rData[3];
        }
        else if (answer.type == 28)
        { // AAAA record (IPv6)
            for (size_t i = 0; i < answer.rData.size(); i += 2)
            {
                std::cout << std::hex << ((int)answer.rData[i] << 8 | (int)answer.rData[i + 1]);
                if (i + 2 < answer.rData.size())
                    std::cout << ":";
            }
        }
        std::cout << std::endl;
    }
    std::cout << std::endl;
}

// Function to print the Authority Section
void printAuthoritySection(const std::vector<ResourceRecord> &authorities)
{
    std::cout << "[Authority Section]" << std::endl;
    for (const auto &authority : authorities)
    {
        std::cout << authority.name << ". "
                  << authority.ttl << " "
                  << "IN NS " << authority.rData.data() << std::endl; // Assuming rData is a domain name in the NS record
    }
    std::cout << std::endl;
}

// Function to print the Additional Section
void printAdditionalSection(const std::vector<ResourceRecord> &additionals)
{
    std::cout << "[Additional Section]" << std::endl;
    for (const auto &additional : additionals)
    {
        std::cout << additional.name << ". "
                  << additional.ttl << " "
                  << "IN "
                  << (additional.type == 1 ? "A" : std::to_string(additional.type)) << " ";
        // Print IP address or other data depending on record type
        if (additional.type == 1)
        { // A record (IPv4)
            std::cout << (int)additional.rData[0] << "." << (int)additional.rData[1] << "."
                      << (int)additional.rData[2] << "." << (int)additional.rData[3];
        }
        std::cout << std::endl;
    }
    std::cout << std::endl;
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

void parseDNSPacket(const std::vector<uint8_t> &packet)
{
    size_t offset = 0;

    // Parse Header
    DNSHeader header;
    header.id = (packet[offset] << 8) | packet[offset + 1];
    header.flags = (packet[offset + 2] << 8) | packet[offset + 3];
    header.qdCount = (packet[offset + 4] << 8) | packet[offset + 5];
    header.anCount = (packet[offset + 6] << 8) | packet[offset + 7];
    header.nsCount = (packet[offset + 8] << 8) | packet[offset + 9];
    header.arCount = (packet[offset + 10] << 8) | packet[offset + 11];
    offset += 12;

    // Parse Question Section
    std::vector<QuestionSection> questions;
    for (int i = 0; i < header.qdCount; i++)
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
    for (int i = 0; i < header.anCount; i++)
    {
        ResourceRecord answer;
        answer.name = readDomainName(packet, offset);
        answer.type = (packet[offset] << 8) | packet[offset + 1];
        answer.classCode = (packet[offset + 2] << 8) | packet[offset + 3];
        answer.ttl = (packet[offset + 4] << 24) | (packet[offset + 5] << 16) | (packet[offset + 6] << 8) | packet[offset + 7];
        answer.rdLength = (packet[offset + 8] << 8) | packet[offset + 9];
        offset += 10;
        answer.rData = std::vector<uint8_t>(packet.begin() + offset, packet.begin() + offset + answer.rdLength);
        offset += answer.rdLength;
        answers.push_back(answer);
    }

    // Parse Authority Section
    std::vector<ResourceRecord> authorities;
    for (int i = 0; i < header.nsCount; i++)
    {
        ResourceRecord authority;
        authority.name = readDomainName(packet, offset);
        authority.type = (packet[offset] << 8) | packet[offset + 1];
        authority.classCode = (packet[offset + 2] << 8) | packet[offset + 3];
        authority.ttl = (packet[offset + 4] << 24) | (packet[offset + 5] << 16) | (packet[offset + 6] << 8) | packet[offset + 7];
        authority.rdLength = (packet[offset + 8] << 8) | packet[offset + 9];
        offset += 10;
        authority.rData = std::vector<uint8_t>(packet.begin() + offset, packet.begin() + offset + authority.rdLength);
        offset += authority.rdLength;
        authorities.push_back(authority);
    }

    // Parse Additional Section
    std::vector<ResourceRecord> additionals;
    for (int i = 0; i < header.arCount; i++)
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

    // Call the print functions to display the sections
    if (header.qdCount > 0)
    {
        printQuestionSection(questions);
    }
    if (header.anCount > 0)
    {
        printAnswerSection(answers);
    }
    if (header.nsCount > 0)
    {
        printAuthoritySection(authorities);
    }
    if (header.arCount > 0)
    {
        printAdditionalSection(additionals);
    }

}
