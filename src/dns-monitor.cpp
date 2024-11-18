/**
 * @file dns-monitor.cpp
 * @author Vojtěch Kuchař xkucha30
 * @brief Main entry point for the DNS monitoring application.
 * @version 1.0
 * @date 2024-11-17
 *
 * @copyright Copyright (c) 2024
 *
 */

#include "../include/app.h"

int main(int argc, char *argv[])
{
    DNSMonitor monitor(argc, argv);
    return monitor.run();
}