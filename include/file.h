#pragma once
#include "include.h"
#include "argumentParser.h"

class fileHandler
{
public:
    explicit fileHandler(const inputArguments &args);
    bool writeLine(const std::string &line);
    bool removeEmptyLines(); // New method to remove empty lines

private:
    inputArguments args;
    std::ofstream file;
    std::string filePath;

    bool openFile(std::string openFile);
    void closeFile();
    std::string removeTrailingDots(const std::string &line);
};
