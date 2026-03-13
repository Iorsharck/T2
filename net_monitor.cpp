#include "net_monitor.h"

#include <iostream>
#include <fstream>
#include <thread>
#include <chrono>
#include <cstring>

#include <ifaddrs.h>
#include <arpa/inet.h>
#include <net/if.h>
#include <unistd.h>

using json = nlohmann::json;

NetMonitor::NetMonitor(const std::string& iface, JSONLogger& log)
{
    interfaceName = iface;
    logger = log;
    ipChangeCount = 0;
}

bool NetMonitor::interfaceExists()
{
    std::string path = "/sys/class/net/" + interfaceName;

    if(access(path.c_str(), F_OK) != 0)
    {
        std::cerr << "Error: Interface does not exist -> "
                  << interfaceName << std::endl;
        return false;
    }

    return true;
}

std::string NetMonitor::getMAC()
{
    std::string path =
        "/sys/class/net/" + interfaceName + "/address";

    std::ifstream file(path);

    if(!file.is_open())
    {
        std::cerr << "Error reading MAC address" << std::endl;
        return "";
    }

    std::string mac;
    file >> mac;

    return mac;
}

std::string NetMonitor::getIP()
{
    struct ifaddrs *ifaddr, *ifa;

    if(getifaddrs(&ifaddr) == -1)
    {
        std::cerr << "getifaddrs failed" << std::endl;
        return "";
    }

    std::string ip;

    for(ifa = ifaddr; ifa != nullptr; ifa = ifa->ifa_next)
    {
        if(ifa->ifa_addr == nullptr)
            continue;

        if(ifa->ifa_addr->sa_family == AF_INET)
        {
            if(interfaceName == ifa->ifa_name)
            {
                char host[NI_MAXHOST];

                struct sockaddr_in *sa =
                    (struct sockaddr_in *)ifa->ifa_addr;

                if(inet_ntop(AF_INET,
                             &sa->sin_addr,
                             host,
                             NI_MAXHOST))
                {
                    ip = host;
                }
            }
        }
    }

    freeifaddrs(ifaddr);

    return ip;
}

void NetMonitor::monitor(unsigned int interval_ms)
{
    if(!interfaceExists())
        return;

    currentMAC = getMAC();
    currentIP = getIP();

    std::cout << "Monitoring interface: "
              << interfaceName << std::endl;

    while(true)
    {
        std::this_thread::sleep_for(
            std::chrono::milliseconds(interval_ms));

        std::string newMAC = getMAC();
        std::string newIP = getIP();

        if(newMAC.empty())
            continue;

        if(newMAC != currentMAC)
        {
            std::cout << "[ALERT] MAC changed\n";

            json log = {
                {"type","alert"},
                {"event","mac_changed"},
                {"interface",interfaceName},
                {"old_mac",currentMAC},
                {"new_mac",newMAC}
            };

            logger.logJSON(log.dump());

            currentMAC = newMAC;
        }

        if(newIP != currentIP)
        {
            std::cout << "[INFO] IP changed\n";

            ipChangeCount++;

            json log = {
                {"type","event"},
                {"event","ip_changed"},
                {"interface",interfaceName},
                {"old_ip",currentIP},
                {"new_ip",newIP},
                {"change_count",ipChangeCount}
            };

            logger.logJSON(log.dump());

            currentIP = newIP;

            if(ipChangeCount > 10)
            {
                json alert = {
                    {"type","alert"},
                    {"event","excessive_ip_changes"},
                    {"interface",interfaceName},
                    {"changes",ipChangeCount}
                };

                logger.logJSON(alert.dump());

                ipChangeCount = 0;
            }
        }
    }
}