/**
 * @file argumentParser.h
 * @author Vojtěch Kuchař (xkucha30@stud.fit.vutbr.cz)
 * @brief Handles the input arguments.
 * @version 0.1
 * @date 2023-11-20
 * 
 * @copyright Copyright (c) 2023
 * 
 */

#pragma once

#include "include.h"

// Struct for storing input arguments.
struct inputArguments
{
    int port = 389;
    string file;
};


class argumentParser
{
public:
    /**
     * @brief Handles the input arguments. Prints help if needed.
     * 
     * @param argc Length of argv.
     * @param argv Array of arguments.
     * @param out Struct for storing the arguments.
     */
    static void parseArguments(int argc, char *argv[], inputArguments &out);
    struct inputArguments arguments;
};
