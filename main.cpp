#include "sniffer.h"
#include "net_monitor.h"
#include "logger.h"

#include <iostream>
#include <thread>
#include <limits>
#include <unistd.h>

bool interfaceExists(const std::string& iface)
{
    std::string path = "/sys/class/net/" + iface;
    return access(path.c_str(), F_OK) == 0;
}

bool isNumber(const std::string& str)
{
    for(char c : str)
    {
        if(!isdigit(c))
            return false;
    }
    return !str.empty();
}

int main()
{
    std::string iface;
    std::string inputInterval;
    std::string inputBytes;

    std::cout << "Network Interface: ";
    std::cin >> iface;

    if(!interfaceExists(iface))
    {
        std::cerr << "Error: Interface does not exist.\n";
        return 1;
    }

    std::cout << "Sniffer interval (ms): ";
    std::cin >> inputInterval;

    if(!isNumber(inputInterval))
    {
        std::cerr << "Error: Interval must be a positive number.\n";
        return 1;
    }

    int interval = std::stoi(inputInterval);

    if(interval <= 0)
    {
        std::cerr << "Error: Interval must be greater than 0.\n";
        return 1;
    }

    std::cout << "Bytes to store from packets: ";
    std::cin >> inputBytes;

    if(!isNumber(inputBytes))
    {
        std::cerr << "Error: Bytes must be numeric.\n";
        return 1;
    }

    int bytes = std::stoi(inputBytes);

    if(bytes <= 0 || bytes > 65535)
    {
        std::cerr << "Error: Invalid byte size.\n";
        return 1;
    }

    if(geteuid() != 0)
    {
        std::cerr << "Warning: Program not running as root.\n";
        std::cerr << "Sniffer may fail due to insufficient permissions.\n";
    }

    JSONLogger logger("logs.json");

    try
    {
        Sniffer sniffer(iface, bytes, logger);
        NetMonitor monitor(iface, logger);

        std::thread snifferThread([&sniffer]()
        {
            try
            {
                sniffer.startSniffing();
            }
            catch(...)
            {
                std::cerr << "Sniffer thread crashed.\n";
            }
        });

        std::thread monitorThread([&monitor, interval]()
        {
            try
            {
                monitor.monitor(interval);
            }
            catch(...)
            {
                std::cerr << "NetMonitor thread crashed.\n";
            }
        });

        snifferThread.join();
        monitorThread.join();
    }
    catch(const std::exception& e)
    {
        std::cerr << "Fatal error: " << e.what() << std::endl;
        return 1;
    }

    return 0;
}