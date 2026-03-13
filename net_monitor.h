#ifndef NET_MONITOR_H
#define NET_MONITOR_H

#include <string>
#include "logger.h"

class NetMonitor
{
private:
    std::string interfaceName;
    std::string currentIP;
    std::string currentMAC;

    int ipChangeCount;

    JSONLogger& logger;

    std::string getMAC();
    std::string getIP();
    bool interfaceExists();

public:
    NetMonitor(const std::string& iface, JSONLogger& log);

    void monitor(unsigned int interval_ms);
};

#endif