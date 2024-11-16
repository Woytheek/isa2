#include "../include/translation.h"

void Translation::loadTranslation(std::string domain, std::string ip)
{
    this->translations.push_back({domain, ip});
}

void Translation::printTranslations()
{
    // otevri translations.txt

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

// Closes the file
void Translation::closeFile()
{
    if (file.is_open())
    {
        file.close();
    }
}

// Function to remove trailing dots from each word
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
    std::ifstream inputFile(filePath); // Open the file for reading
    if (!inputFile.is_open())
    {
        return false; // Failed to open file
    }

    std::ostringstream outputStream; // String stream to accumulate non-empty lines
    std::string line;

    // Read each line
    while (std::getline(inputFile, line))
    {
        // Trim leading and trailing whitespaces
        line = removeTrailingDots(line); // Optional: can modify this to trim whitespace
        if (!line.empty())
        { // Only write non-empty lines
            outputStream << line << "\n";
        }
    }

    inputFile.close();

    // Open the file for writing (overwrite)
    file.open(filePath, std::ios::out | std::ios::trunc);
    if (!file.is_open())
    {
        return false; // Failed to open file for writing
    }

    // Write the cleaned content back to the file
    file << outputStream.str();
    closeFile();
    return true;
}

// Writes a line to the file
bool Translation::writeLine(const std::string &line, std::string &filePath)
{
    std::string newLine = removeTrailingDots(line);

    // check if newline contains no dots
    if (newLine.find('.') == std::string::npos)
    {
        return false;
    }

    // Ensure file is open for both reading and writing
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
        inFile.close(); // Close the file after checking
    }

    // If the line doesn't exist, write it to the file
    if (!lineExists)
    {
        file << newLine << std::endl;
    }

    closeFile();
    return true;
}
