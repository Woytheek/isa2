#pragma once
#include "include.h"

struct TranslationStruct
{
    std::string domainName;
    std::string ip;
};

class Translation
{
public:
    std::string dfilepath; // Domain file path
    std::string tfilepath; // Translation file path

    // Constructor that accepts file paths
    Translation(const std::string &dfile, const std::string &tfile)
        : dfilepath(dfile), tfilepath(tfile) {}

    std::vector<TranslationStruct> translations;
    void loadTranslation(std::string domainName, std::string ip="");
    void printDomains();
    void printTranslations();
    bool writeLine(const std::string &line, std::string &filePath);
    bool removeEmptyLines(std::string &filePath);

private:
    std::ofstream file;
    bool openFile(std::string openFile);
    void closeFile();
    std::string removeTrailingDots(const std::string &line);
};