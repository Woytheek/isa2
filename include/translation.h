/**
 * @file translation.h
 * @author Vojtěch Kuchař xkucha30
 * @brief Provides functionality for managing domain translations and file operations.
 *        Includes methods for loading, printing, and manipulating domain-IP mappings,
 *        as well as handling related file I/O tasks.
 * @version 1.0
 * @date 2024-11-17
 *
 * @copyright Copyright (c) 2024
 *
 */

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
    std::string dfilepath;                       // Domain file path
    std::string tfilepath;                       // Translation file path
    std::vector<TranslationStruct> translations; // Vector to store domain-IP translations

    /**
     * @brief Constructs a `Translation` object with specified domain and translation file paths.
     *        Initializes the file paths for the domain file and the translation file.
     *
     * @param dfile The path to the domain file that stores domain names.
     * @param tfile The path to the translation file that stores domain-IP mappings.
     */
    Translation(const std::string &dfile, const std::string &tfile)
        : dfilepath(dfile), tfilepath(tfile) {}

    /**
     * @brief Loads a domain-IP translation into the translations vector.
     *        If no IP is provided, the translation is recorded with an empty IP.
     *
     * @param domain The domain name to be translated.
     * @param ip The IP address associated with the domain (defaults to an empty string if not provided).
     */
    void loadTranslation(std::string domainName, std::string ip = "");

    /**
     * @brief Prints all domain names, writing them to the domain file.
     *        This will only print the domain name, without the associated IP address.
     */
    void printDomains();

    /**
     * @brief Prints all domain-IP translations, writing them to the translation file.
     *        Only translations with a non-empty IP are printed.
     */
    void printTranslations();

    /**
     * @brief Writes a line to a file, ensuring the line does not already exist in the file.
     *        It also removes any trailing dots from the line before writing.
     *
     * @param line The line to write.
     * @param filePath The path of the file to write the line to.
     * @return True if the line was written successfully, false if the line already exists or the file could not be opened.
     */
    bool writeLine(const std::string &line, std::string &filePath);

    /**
     * @brief Removes empty lines from a file. The function reads the file, filters out empty lines,
     *        and writes the cleaned content back to the file, overwriting its original content.
     *
     * @param filePath The path to the file that will be processed. The file is read, cleaned,
     *                 and then rewritten with the non-empty lines.
     * @return True if the file was successfully processed and saved, false otherwise.
     */
    bool removeEmptyLines(std::string &filePath);

private:
    std::ofstream file;

    /**
     * @brief Opens a file for appending or writing. If the file cannot be opened, prints an error message.
     *
     * @param openFile The file path to open.
     * @return True if the file was opened successfully, false otherwise.
     */
    bool openFile(std::string openFile);

    /**
     * @brief Closes the currently open file, if any.
     */
    void closeFile();
    std::string removeTrailingDots(const std::string &line);
};