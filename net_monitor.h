#ifndef NET_MONITOR_H
#define NET_MONITOR_H

#include <string>
#include "logger.h"

class NetMonitor
{
private:
    std::string iface;
    std::string currentIP;
    std::string currentMAC;

    int ipChangeCount;
    JSONLogger& logger;

    std::string getIP();
    std::string getMAC();

public:
    NetMonitor(const std::string& iface,JSONLogger& log);
    void monitor(int interval);
};

#endif
