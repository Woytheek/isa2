#include "../include/file.h"

// Constructor that takes input arguments
fileHandler::fileHandler(const inputArguments &args) : args(args) {}

// Opens the file specified in args.domainsFile
bool fileHandler::openFile()
{
    file.open(args.domainsFile, std::ios::out | std::ios::app);
    if (!file.is_open())
    {
        std::cerr << "Error: Could not open file " << args.domainsFile << "\n";
        return false;
    }
    return true;
}

// Closes the file
void fileHandler::closeFile()
{
    if (file.is_open())
    {
        file.close();
    }
}

// Function to remove trailing dots from each word
std::string fileHandler::removeTrailingDots(const std::string &line)
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

bool fileHandler::removeEmptyLines()
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
bool fileHandler::writeLine(const std::string &line)
{
    std::string newLine = removeTrailingDots(line);
    if (!openFile()) // Ensure file is open before proceeding
    {
        return false;
    }

    // First, check if the line already exists in the file
    std::string currentLine;

    bool lineExists = false;

    // Read the file to check for existing line
    if (args.d)
    {
        filePath = args.domainsFile;
    }
    if (args.t)
    {
        filePath = args.translationsFile;
    }
    std::ifstream inFile(filePath); // Assumes filePath is a member variable
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