#include "../include/dns.h"

void DNSParser::parseRawPacket(unsigned char *packet, ssize_t size, struct pcap_pkthdr captureHeader, int offset)
{
    char *dateTime = getPacketTimestamp(captureHeader); // Získání časového razítka

    // Proměnné pro hlavičky IP a DNS
    struct ip6_hdr *ip6_header;
    struct ip *ipHeader;

    // Vytvoření instance třídy IPInfo pro uchování informací o IP
    IPInfo ipInfo; // Používáme přímou instanci třídy

    unsigned char *dnsPayload;
    ssize_t dnsSize;

    // Zpracování IPv4 paketu
    if (packet[offset] == 0x45 && packet[offset + 1] == 0x00 && packet[offset - 1] == 0x00 && packet[offset - 2] == 0x08)
    {
        ipHeader = (struct ip *)(packet + offset); // Přeskočení Ethernet hlavičky
        inet_ntop(AF_INET, &(ipHeader->ip_src), ipInfo.srcIP, INET_ADDRSTRLEN);
        inet_ntop(AF_INET, &(ipHeader->ip_dst), ipInfo.dstIP, INET_ADDRSTRLEN);

        // Přeskočíme Ethernet, IP a UDP hlavičky k dosažení DNS sekce
        dnsPayload = packet + offset + (ipHeader->ip_hl * 4) + 8; // 8 bajtů pro délku UDP hlavičky

        // Výpočet velikosti DNS: celková velikost - Ethernet hlavička - IP hlavička - UDP hlavička
        dnsSize = size - (offset + (ipHeader->ip_hl * 4) + 8);
        ipInfo.srcPort = ntohs(((struct udphdr *)(packet + offset + (ipHeader->ip_hl * 4)))->uh_sport);
        ipInfo.dstPort = ntohs(((struct udphdr *)(packet + offset + (ipHeader->ip_hl * 4)))->uh_dport);
    }

    // Zpracování IPv6 paketu
    if (packet[offset] == 0x60)
    {
        ipInfo.isIPv6 = true;
        ip6_header = (struct ip6_hdr *)(packet + offset); // Nastavíme ukazatel na začátek IP6 hlavičky
        inet_ntop(AF_INET6, &(ip6_header->ip6_src), ipInfo.srcIP6, INET6_ADDRSTRLEN);
        inet_ntop(AF_INET6, &(ip6_header->ip6_dst), ipInfo.dstIP6, INET6_ADDRSTRLEN);

        // Přeskočení IP6 hlavičky
        dnsPayload = packet + offset + sizeof(struct ip6_hdr) + 8;
        dnsSize = size - (offset + sizeof(struct ip6_hdr) + 8); // Výpočet velikosti DNS: celková velikost - IP6 hlavička - UDP hlavička
        ipInfo.srcPort = ntohs(((struct udphdr *)(packet + offset + sizeof(struct ip6_hdr)))->uh_sport);
        ipInfo.dstPort = ntohs(((struct udphdr *)(packet + offset + sizeof(struct ip6_hdr)))->uh_dport);
    }

    // Vytvoření unikátního ukazatele na DNSHeader
    auto header = std::make_unique<DNSHeader>();
    std::vector<uint8_t> dnsBody(dnsPayload, dnsPayload + dnsSize);

    // Parzování DNS hlavičky
    parseDNSHeader(dnsBody, header.get());

    // Vytvoření unikátního ukazatele na DNSSections pro uložení různých sekcí
    auto sections = std::make_unique<DNSSections>();
    parseDNSPacket(dnsBody, header.get(), sections.get());

    // Podle parametrů vypíšeme výstup
    if (args.v)
    {
        printVerboseDNS(dnsBody, header.get(), &ipInfo, sections.get(), dateTime);
    }
    else
    {
        printSimplifiedDNS(header.get(), &ipInfo, dateTime);
    }
    delete[] dateTime;
    return;
}

void DNSParser::parseDNSHeader(const std::vector<uint8_t> &packet, DNSHeader *header)
{
    // Ověření, že paket má dostatečnou délku pro parsování hlavičky
    if (packet.size() < 12)
    {
        std::cerr << "Chyba: Příliš krátký paket pro parsování DNS hlavičky!" << std::endl;
        return;
    }

    // Offset začíná na 0 pro čtení hlavičky
    int offset = 0;

    // Parsování jednotlivých částí DNS hlavičky
    header->id = (packet[offset] << 8) | packet[offset + 1];            // Transaction ID
    header->flags = (packet[offset + 2] << 8) | packet[offset + 3];     // Flags
    header->qdCount = (packet[offset + 4] << 8) | packet[offset + 5];   // Počet dotazů
    header->anCount = (packet[offset + 6] << 8) | packet[offset + 7];   // Počet odpovědí
    header->nsCount = (packet[offset + 8] << 8) | packet[offset + 9];   // Počet autoritativních záznamů
    header->arCount = (packet[offset + 10] << 8) | packet[offset + 11]; // Počet dalších záznamů

    // Pokud je třeba, můžeme přidat další zpracování nebo validace
    // Například ověření některých polí nebo konverzi některých hodnot
}
void DNSParser::parseDNSPacket(const std::vector<uint8_t> &packet, DNSHeader *header, DNSSections *sections)
{
    size_t offset = 0;
    offset += 12; // Skip header

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
        // Root domain indicates the end of the additional section
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

    // Uložení zpracovaných sekcí do objektu DNSSections
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

void DNSParser::printSimplifiedDNS(DNSHeader *dnsHeader, IPInfo *ipInfo, char *dateTime)
{
    // Stanovení typu zprávy (Query nebo Response)
    char qr = (dnsHeader->flags & 0x8000) ? 'R' : 'Q';

    // Počty jednotlivých sekcí v DNS paketu
    int qdCount = dnsHeader->qdCount; // Počet dotazů
    int anCount = dnsHeader->anCount; // Počet odpovědí
    int nsCount = dnsHeader->nsCount; // Počet autoritativních záznamů
    int arCount = dnsHeader->arCount; // Počet dodatečných záznamů

    // Kontrola, zda je použitá IPv6
    if (ipInfo->isIPv6)
    {
        // Výpis pro IPv6
        printf("%s %s -> %s (%c %d/%d/%d/%d)\n", dateTime, ipInfo->srcIP6, ipInfo->dstIP6, qr, qdCount, anCount, nsCount, arCount);
    }
    else
    {
        // Výpis pro IPv4
        printf("%s %s -> %s (%c %d/%d/%d/%d)\n", dateTime, ipInfo->srcIP, ipInfo->dstIP, qr, qdCount, anCount, nsCount, arCount);
    }
}
void DNSParser::printVerboseDNS(const std::vector<uint8_t> &packet, DNSHeader *dnsHeader, IPInfo *ipInfo, DNSSections *sections, char *dateTime)
{
    // Výpis časového razítka
    printf("Timestamp: %s\n", dateTime);

    // Výpis IP informací, zajištění správné verze IP (IPv4/IPv6)
    printf("SrcIP: %s\n", ipInfo->isIPv6 ? ipInfo->srcIP6 : ipInfo->srcIP);
    printf("DstIP: %s\n", ipInfo->isIPv6 ? ipInfo->dstIP6 : ipInfo->dstIP);
    printf("SrcPort: UDP/%d\n", ipInfo->srcPort);
    printf("DstPort: UDP/%d\n", ipInfo->dstPort);

    // Výpis DNS hlavičky
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

    // Výpis DNS sekcí (dotazy, odpovědi, autoritativní záznamy, atd.)
    printSections(sections, packet);
    // Oddělení jednotlivých paketů
    printf("====================\n");
}

std::string DNSParser::readDomainName(const std::vector<uint8_t> &data, size_t &offset)
{
    std::string name;

    // Pokračujeme čtením, dokud nenarazíme na nulu, která značí konec domény
    while (data[offset] != 0)
    {
        uint8_t len = data[offset++]; // Získáme délku následujícího segmentu názvu
        if (len >= 192)
        {
            // Pokud je délka větší nebo rovná 192, jedná se o kompresi
            uint16_t pointer = ((len & 0x3F) << 8) | data[offset++]; // Získáme ukazatel na jinou část názvu domény
            size_t tempOffset = pointer;                             // Ukazatel na novou část názvu
            name += readDomainName(data, tempOffset);                // Rekurzivně čteme komprimovanou část domény
            break;                                                   // Po kompresi skončíme čtení
        }
        name += std::string(data.begin() + offset, data.begin() + offset + len) + "."; // Přidáme segment názvu do celkového názvu
        offset += len;                                                                 // Posuneme offset o délku segmentu
    }

    return name; // Vrátíme celý název domény
}

ResourceRecord DNSParser::parseResourceRecord(const std::vector<uint8_t> &data, size_t &offset)
{
    ResourceRecord record;
    // Načteme název domény (záznam, jehož jméno je na začátku)
    record.name = readDomainName(data, offset);

    // Načteme typ záznamu (2 bajty)
    record.type = (data[offset] << 8) | data[offset + 1];

    // Kontrola, zda typ záznamu patří mezi určité hodnoty (1, 2, 5, 6, 15, 28, 33)
    if (record.type != 1 && record.type != 2 && record.type != 5 && record.type != 6 && record.type != 15 && record.type != 28 && record.type != 33)
    {
        record.skip = true; // Pokud ne, nastavíme flag pro přeskočení záznamu
    }

    // Načteme classCode (2 bajty)
    record.classCode = (data[offset + 2] << 8) | data[offset + 3];

    // Načteme TTL (4 bajty)
    record.ttl = (data[offset + 4] << 24) | (data[offset + 5] << 16) | (data[offset + 6] << 8) | data[offset + 7];

    // Načteme délku dat (rData) záznamu (2 bajty)
    record.rdLength = (data[offset + 8] << 8) | data[offset + 9];

    // Posuneme offset o 10 bajtů (to pokrývá název domény, typ, classCode, TTL, a délku dat)
    offset += 10;

    // Načteme samotná data záznamu (rData) podle rdLength
    record.rData = std::vector<uint8_t>(data.begin() + offset, data.begin() + offset + record.rdLength);
    record.rDataOffset = offset; // Uložíme původní offset pro případnou potřebu

    // Posuneme offset o velikost rData
    offset += record.rdLength;

    return record; // Vrátíme strukturu ResourceRecord
}

void DNSParser::printSections(DNSSections *sections, const std::vector<uint8_t> &packet)
{
    (void)packet;
    // Pokud existují otázky v sekci 'questions', vypíšeme je
    if (!sections->questions.empty())
    {
        printQuestionSection(sections->questions);
    }

    // Pokud existují odpovědi v sekci 'answers', vypíšeme je
    if (!sections->answers.empty())
    {
        printf("\n[Answer Section]\n");
        for (const auto &answer : sections->answers)
        {
            printResourceRecord(answer, packet);
        }
    }

    // Pokud existují autoritativní záznamy v sekci 'authorities', vypíšeme je
    if (!sections->authorities.empty())
    {
        printf("\n[Authority Section]\n");
        for (const auto &authority : sections->authorities)
        {
            printResourceRecord(authority, packet);
        }
    }

    // Pokud existují další záznamy v sekci 'additionals', vypíšeme je
    if (!sections->additionals.empty())
    {
        printf("\n[Additional Section]\n");
        for (const auto &additional : sections->additionals)
        {
            printResourceRecord(additional, packet);
        }
    }
}

void DNSParser::printQuestionSection(const std::vector<QuestionSection> &questions)
{
    // Pokud jsou všechny dotazy validní, vypíšeme hlavičku sekce
    printf("\n[Question Section]\n");
    for (const auto &question : questions)
    {
        // Vytiskneme název dotazu
        printf("%s ", question.qName.c_str());

        // Vytiskneme třídu dotazu podle hodnoty qClass
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
void DNSParser::printResourceRecord(const ResourceRecord &record, const std::vector<uint8_t> &packet)
{
    // Kontrola platnosti typu záznamu
    if (record.type != 1 && record.type != 2 && record.type != 5 && record.type != 6 && record.type != 15 && record.type != 28 && record.type != 33)
    {
        return; // Neplatné typy záznamů jsou ignorovány
    }

    // Třída záznamu podle hodnoty classCode
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

    size_t tempOffset = record.rDataOffset;

    // Proměnné pro různé typy záznamů
    std::string dname, ip, exchange, cname, mname, rname, target;
    uint16_t priority, weight, port;
    uint32_t serial, refresh, retry, expire, minimum;

    // Objekt pro překládání
    Translation tran(args.domainsFile, args.translationsFile);

    // Výběr dle typu záznamu
    switch (record.type)
    {
    case 1: // A (IPv4 Address)
    {
        ip = std::to_string((int)record.rData[0]) + "." + std::to_string((int)record.rData[1]) + "." + std::to_string((int)record.rData[2]) + "." + std::to_string((int)record.rData[3]);
        printf("%s %d %s A %s\n", record.name.c_str(), record.ttl, recordClass.c_str(), ip.c_str());
        tran.loadTranslation(record.name, ip);
        break;
    }

    case 2: // NS (Name Server)
    {
        dname = readDomainName(packet, tempOffset);
        printf("%s %d %s NS %s\n", record.name.c_str(), record.ttl, recordClass.c_str(), dname.c_str());
        tran.loadTranslation(record.name);
        tran.loadTranslation(dname);
        break;
    }

    case 5: // CNAME (Canonical Name)
    {
        cname = readDomainName(packet, tempOffset);
        printf("%s %d %s CNAME %s\n", record.name.c_str(), record.ttl, recordClass.c_str(), cname.c_str());
        tran.loadTranslation(record.name);
        tran.loadTranslation(cname);
        break;
    }

    case 6: // SOA (Start of Authority)
    {
        mname = readDomainName(packet, tempOffset);
        rname = readDomainName(packet, tempOffset);
        serial = (packet[tempOffset] << 24) | (packet[tempOffset + 1] << 16) | (packet[tempOffset + 2] << 8) | packet[tempOffset + 3];
        refresh = (packet[tempOffset + 4] << 24) | (packet[tempOffset + 5] << 16) | (packet[tempOffset + 6] << 8) | packet[tempOffset + 7];
        retry = (packet[tempOffset + 8] << 24) | (packet[tempOffset + 9] << 16) | (packet[tempOffset + 10] << 8) | packet[tempOffset + 11];
        expire = (packet[tempOffset + 12] << 24) | (packet[tempOffset + 13] << 16) | (packet[tempOffset + 14] << 8) | packet[tempOffset + 15];
        minimum = (packet[tempOffset + 16] << 24) | (packet[tempOffset + 17] << 16) | (packet[tempOffset + 18] << 8) | packet[tempOffset + 19];
        printf("%s %d %s SOA %s %s %d %d %d %d %d\n", record.name.c_str(), record.ttl, recordClass.c_str(), mname.c_str(), rname.c_str(), serial, refresh, retry, expire, minimum);
        tran.loadTranslation(record.name);
        tran.loadTranslation(mname);
        tran.loadTranslation(rname);
        break;
    }

    case 15: // MX (Mail Exchange)
    {
        size_t MXtempOffset = tempOffset + 2;
        exchange = readDomainName(packet, MXtempOffset);
        uint16_t preference = (record.rData[0] << 8) | record.rData[1];
        printf("%s %d %s MX %d %s\n", record.name.c_str(), record.ttl, recordClass.c_str(), preference, exchange.c_str());
        tran.loadTranslation(record.name);
        tran.loadTranslation(exchange);
        break;
    }

    case 28: // AAAA (IPv6 Address)
    {
        std::string ipv6 = ipv6ToString(record.rData);
        printf("%s %d %s AAAA %s", record.name.c_str(), record.ttl, recordClass.c_str(), ipv6.c_str());
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
        printf("%s %d %s SRV %d %d %d %s\n", record.name.c_str(), record.ttl, recordClass.c_str(), priority, weight, port, target.c_str());
        tran.loadTranslation(target);
        break;
    }

    default:
        break; // Neznámý typ záznamu (nepotřebujeme jej zpracovávat)
    }

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
        // Print each byte in hex format with leading zeros
        printf("%02x", data[i]);
        if (i < size - 1)
        {
            printf(" "); // Print space between bytes
        }
    }
    printf("\n"); // End with a newline
}
void printIPv6(const std::vector<uint8_t> &rData)
{
    // Ensure the rData size is correct for IPv6
    if (rData.size() != 16)
    {
        printf("Invalid IPv6 address data size.\n");
        return;
    }

    // Step 1: Convert 16 bytes to 8 16-bit blocks
    uint16_t blocks[8];
    for (size_t i = 0; i < 8; ++i)
    {
        blocks[i] = (rData[2 * i] << 8) | rData[2 * i + 1];
    }

    // Step 2: Find the longest run of zero blocks for "::" compression
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

    // Step 3: Print the blocks with compression
    for (int i = 0; i < 8; ++i)
    {
        if (i == best_zero_start)
        { // Start of "::" compression
            printf("::");
            i += max_zeros - 1; // Skip over the zero sequence
            continue;
        }
        if (i > 0 && i != best_zero_start + max_zeros)
        {
            printf(":");
        }
        printf("%x", blocks[i]);
    }
    printf("\n");
}

std::string DNSParser::ipv6ToString(const std::vector<uint8_t> &rData)
{
    std::string ipv6;
    // Ensure the rData size is correct for IPv6
    if (rData.size() != 16)
    {
        return "Invalid IPv6 address data size.";
    }

    // Step 1: Convert 16 bytes to 8 16-bit blocks
    uint16_t blocks[8];
    for (size_t i = 0; i < 8; ++i)
    {
        blocks[i] = (rData[2 * i] << 8) | rData[2 * i + 1];
    }

    // Step 2: Find the longest run of zero blocks for "::" compression
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

    // Step 3: Print the blocks with compression
    for (int i = 0; i < 8; ++i)
    {
        if (i == best_zero_start)
        { // Start of "::" compression
            ipv6 += "::";
            i += max_zeros - 1; // Skip over the zero sequence
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
    // Zkontrolujeme, zda je délka paketu dostatečná pro Ethernet a IP hlavičky
    if (length < 42) // 14 (Ethernet) + 20 (IP) + 8 (UDP) = 42
    {
        return -1; // Nejde o DNS paket, protože je příliš krátký
    }

    for (int offset = 0; offset < length - 1; offset++)
    {
        // Kontrola pro IPv4
        if (packet[offset] == 0x45 && packet[offset + 1] == 0x00 && packet[offset - 1] == 0x00 && packet[offset - 2] == 0x08)
        {
            // Vytvoření objektu pro uchování informací o IP

            IPInfo ipInfo;
            struct ip *ip_header = (struct ip *)(packet + offset);

            // Uložení IPv4 adres do objektu IPInfo
            inet_ntop(AF_INET, &(ip_header->ip_src), ipInfo.srcIP, INET_ADDRSTRLEN);
            inet_ntop(AF_INET, &(ip_header->ip_dst), ipInfo.dstIP, INET_ADDRSTRLEN);
            ipInfo.srcPort = 0; // Tento detail by bylo nutné získat z UDP hlavičky (pokud by bylo potřeba)
            ipInfo.dstPort = 0; // Stejně jako u srcPort

            // Kontrola, zda je protokol UDP
            if (ip_header->ip_p != IPPROTO_UDP)
            {
                return -1; // Nejde o UDP paket
            }

            // Posun na začátek UDP hlavičky
            struct udphdr *udp = (struct udphdr *)(packet + offset + (ip_header->ip_hl * 4));

            // Kontrola portů UDP (zdrojový nebo cílový port 53 pro DNS)
            if (ntohs(udp->uh_sport) == 53 || ntohs(udp->uh_dport) == 53)
            {
                return offset; // Tento paket je DNS
            }
        }

        // Kontrola pro IPv6 (nový kód)
        if (packet[offset] == 0x60 && packet[offset + 1] == 0x00 && packet[offset - 1] == 0xDD && packet[offset - 2] == 0x86)
        {
            // Vytvoření objektu pro uchování informací o IPv6
            IPInfo ipInfo;
            struct ip6_hdr *ip6_header = (struct ip6_hdr *)(packet + offset);

            // Uložení IPv6 adres do objektu IPInfo
            inet_ntop(AF_INET6, &(ip6_header->ip6_src), ipInfo.srcIP6, INET6_ADDRSTRLEN);
            inet_ntop(AF_INET6, &(ip6_header->ip6_dst), ipInfo.dstIP6, INET6_ADDRSTRLEN);
            ipInfo.isIPv6 = true; // Určujeme, že se jedná o IPv6 paket

            // Zkontrolujeme, zda je Next Header UDP (17 pro UDP)
            if (ip6_header->ip6_nxt != IPPROTO_UDP)
            {
                return -1; // Nejde o UDP
            }

            // Posun na začátek UDP hlavičky
            struct udphdr *udp = (struct udphdr *)(packet + offset + sizeof(struct ip6_hdr));

            // Kontrola portů UDP (zdrojový nebo cílový port 53 pro DNS)
            if (ntohs(udp->uh_sport) == 53 || ntohs(udp->uh_dport) == 53)
            {
                return offset; // Tento paket je DNS
            }
        }
    }

    return -1; // Nejedná se o DNS paket
}

char *DNSParser::getPacketTimestamp(struct pcap_pkthdr header)
{
    char *dateTime = new char[20]; // Dynamicky alokované pole pro uložení formátovaného času
    struct tm *timeinfo;

    if (args.p)
    {
        timeinfo = localtime(&header.ts.tv_sec); // Konverze sekund z PCAP timestamp na čas
    }
    else
    {
        // Pokud je paket zachycen živě
        time_t rawtime;
        time(&rawtime);                 // Získání aktuálního času
        timeinfo = localtime(&rawtime); // Konverze na lokální čas
    }

    // Formátování času do řetězce ve formátu "YYYY-MM-DD HH:MM:SS"
    strftime(dateTime, 20, "%Y-%m-%d %H:%M:%S", timeinfo);

    return dateTime; // Vrátí formátovaný čas jako řetězec
}
