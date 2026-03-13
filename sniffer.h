#ifndef SNIFFER_H
#define SNIFFER_H

#include <string>
#include <unordered_map>
#include <unordered_set>
#include "logger.h"

class Sniffer
{
private:
    std::string interfaceName;
    int captureBytes;
    int rawSocket;
    JSONLogger& logger;

    struct SynTracker
    {
        std::unordered_set<std::string> dstIPs;
        std::unordered_set<int> dstPorts;
    };

    std::unordered_map<std::string,int> arpCounter;
    std::unordered_map<std::string,SynTracker> synTracker;

    void processPacket(unsigned char* buffer, int size);
    void detectARP(const std::string& srcIP);
    void detectSYN(const std::string& srcIP,const std::string& dstIP,int port);

public:
    Sniffer(const std::string& iface,int bytes,JSONLogger& log);
    ~Sniffer();

    void startSniffing();
};

#endif
