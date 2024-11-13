#include "../include/app.h"

int main(int argc, char *argv[])
{
    DNSMonitor monitor(argc, argv);
    return monitor.run();
}