#include "net_monitor.h"

#include <iostream>
#include <fstream>
#include <thread>
#include <chrono>
#include <ifaddrs.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <netdb.h>

using json = nlohmann::json;

NetMonitor::NetMonitor(const std::string& i,JSONLogger& log)
:iface(i),logger(log)
{
    ipChangeCount=0;
}

std::string NetMonitor::getMAC()
{
    std::ifstream file("/sys/class/net/"+iface+"/address");

    std::string mac;
    file>>mac;

    return mac;
}

std::string NetMonitor::getIP()
{
    struct ifaddrs *ifaddr,*ifa;

    getifaddrs(&ifaddr);

    std::string ip;

    for(ifa=ifaddr;ifa!=NULL;ifa=ifa->ifa_next)
    {
        if(!ifa->ifa_addr) continue;

        if(ifa->ifa_addr->sa_family==AF_INET && iface==ifa->ifa_name)
        {
            char host[NI_MAXHOST];

            inet_ntop(AF_INET,
                      &((struct sockaddr_in*)ifa->ifa_addr)->sin_addr,
                      host,
                      NI_MAXHOST);

            ip=host;
        }
    }

    freeifaddrs(ifaddr);

    return ip;
}

void NetMonitor::monitor(int interval)
{
    currentIP=getIP();
    currentMAC=getMAC();

    while(true)
    {
        std::this_thread::sleep_for(std::chrono::milliseconds(interval));

        std::string newIP=getIP();
        std::string newMAC=getMAC();

        if(newMAC!=currentMAC)
        {
            json alert={
                {"type","event"},
                {"event","mac_changed"},
                {"old_mac",currentMAC},
                {"new_mac",newMAC}
            };

            logger.logJSON(alert.dump());

            currentMAC=newMAC;
        }

        if(newIP!=currentIP)
        {
            ipChangeCount++;

            json log={
                {"type","event"},
                {"event","ip_changed"},
                {"old_ip",currentIP},
                {"new_ip",newIP}
            };

            logger.logJSON(log.dump());

            currentIP=newIP;

            if(ipChangeCount>10)
            {
                json alert={
                    {"type","anomaly"},
                    {"alert","excessive_ip_changes"}
                };

                logger.logJSON(alert.dump());

                ipChangeCount=0;
            }
        }
    }
}

