#include "../include/translation.h"

void Translation::loadTranslation(std::string domain, std::string ip)
{
    this->translations.push_back({domain, ip});
}

void Translation::printTranslations()
{
    for (auto &translation : this->translations)
    {
        printf("Translation: %s %s\n", translation.domain.c_str(), translation.ip.c_str());
    }
}