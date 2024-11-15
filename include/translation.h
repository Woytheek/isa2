#include "include.h"

struct TranslationStruct
{
    std::string domain;
    std::string ip;
};

class Translation
{
public:
    std::vector<TranslationStruct> translations;
    void loadTranslation(std::string domain, std::string ip);
    void printTranslations();

private:
};