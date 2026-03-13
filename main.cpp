#include "sniffer.h"
#include "net_monitor.h"
#include "logger.h"

#include <iostream>
#include <thread>
#include <unistd.h>

bool interfaceExists(const std::string& iface)
{
    std::string path="/sys/class/net/"+iface;
    return access(path.c_str(),F_OK)==0;
}

int main()
{
    std::string iface;
    int interval;
    int bytes;

    std::cout<<"Interface: ";
    std::cin>>iface;

    if(!interfaceExists(iface))
    {
        std::cerr<<"Interface not found\n";
        return 1;
    }

    std::cout<<"Net monitor interval (ms): ";
    std::cin>>interval;

    if(interval<=0)
    {
        std::cerr<<"Invalid interval\n";
        return 1;
    }

    std::cout<<"Bytes to store per packet: ";
    std::cin>>bytes;

    if(bytes<=0 || bytes>65535)
    {
        std::cerr<<"Invalid byte value\n";
        return 1;
    }

    if(geteuid()!=0)
        std::cerr<<"Warning: RAW sockets require root\n";

    JSONLogger logger("logs.json");

    try
    {
        Sniffer sniffer(iface,bytes,logger);
        NetMonitor monitor(iface,logger);

        std::thread t1([&](){sniffer.startSniffing();});
        std::thread t2([&](){monitor.monitor(interval);});

        t1.join();
        t2.join();
    }
    catch(const std::exception& e)
    {
        std::cerr<<"Fatal error: "<<e.what()<<"\n";
    }

    return 0;
}
