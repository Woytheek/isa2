/**
 * @file translation.cpp
 * @author Vojtěch Kuchař xkucha30
 * @brief Implements functionality for managing domain translations and file operations.
 * @version 1.0
 * @date 2024-11-17
 *
 * @copyright Copyright (c) 2024
 *
 */

#include "../include/translation.h"

void Translation::loadTranslation(std::string domain, std::string ip)
{
    this->translations.push_back({domain, ip});
}

void Translation::printTranslations()
{
    for (auto &translation : this->translations)
    {
        if (translation.ip.empty())
        {
            continue;
        }
        writeLine(translation.domainName + " " + translation.ip, this->tfilepath);
    }
}

void Translation::printDomains()
{
    for (auto &translation : this->translations)
    {
        writeLine(translation.domainName, this->dfilepath);
    }
}

bool Translation::openFile(std::string openFile)
{
    file.open(openFile, std::ios::out | std::ios::app);
    if (!file.is_open())
    {
        std::cerr << "Error: Could not open file " << openFile << "\n";
        return false;
    }
    return true;
}

void Translation::closeFile()
{
    if (file.is_open())
    {
        file.close();
    }
}

std::string Translation::removeTrailingDots(const std::string &line)
{
    std::stringstream ss(line);
    std::string word;
    std::string result;

    while (ss >> word)
    {
        // Remove any trailing dots
        while (!word.empty() && word.back() == '.')
        {
            word.pop_back();
        }

        // Add the modified word to the result
        if (!result.empty())
        {
            result += " ";
        }
        result += word;
    }

    return result;
}

bool Translation::removeEmptyLines(std::string &filePath)
{
    std::ifstream inputFile(filePath);
    if (!inputFile.is_open())
    {
        return false;
    }

    std::ostringstream outputStream; // String stream to accumulate non-empty lines
    std::string line;

    // Read each line
    while (std::getline(inputFile, line))
    {
        // Trim leading and trailing whitespaces
        line = removeTrailingDots(line);
        if (!line.empty())
        {
            outputStream << line << "\n";
        }
    }

    inputFile.close();

    // Open the file for writing (overwrite)
    file.open(filePath, std::ios::out | std::ios::trunc);
    if (!file.is_open())
    {
        return false;
    }

    file << outputStream.str();
    closeFile();
    return true;
}

bool Translation::writeLine(const std::string &line, std::string &filePath)
{
    std::string newLine = removeTrailingDots(line);

    // check if newline contains no dots
    if (newLine.find('.') == std::string::npos)
    {
        return false;
    }

    if (!openFile(filePath))
    {
        return false;
    }

    // Check if the line already exists in the file
    std::string currentLine;
    bool lineExists = false;
    std::ifstream inFile(filePath); // Open the file to read contents

    if (inFile.is_open())
    {
        while (std::getline(inFile, currentLine))
        {
            if (currentLine == newLine) // Line found
            {
                lineExists = true;
                break;
            }
        }
        inFile.close();
    }

    if (!lineExists)
    {
        file << newLine << std::endl;
    }

    closeFile();
    return true;
}
