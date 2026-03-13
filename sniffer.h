#ifndef SNIFFER_H
#define SNIFFER_H

#include <pcap.h>
#include <string>
#include <unordered_map>
#include <unordered_set>
#include <chrono>
#include "logger.h"

class Sniffer
{
private:
    std::string interfaceName;
    int captureBytes;
    pcap_t* handle;
    JSONLogger& logger;

    struct SynTracker
    {
        std::unordered_set<std::string> dstIPs;
        std::unordered_set<int> dstPorts;
        std::chrono::steady_clock::time_point lastSeen;
    };

    std::unordered_map<std::string, int> arpCounter;
    std::unordered_map<std::string, SynTracker> synTracker;

    std::chrono::steady_clock::time_point lastReset;

    static void packetHandler(u_char *user,
                              const struct pcap_pkthdr *header,
                              const u_char *packet);

    void processPacket(const struct pcap_pkthdr *header, const u_char *packet);
    void detectARP(const std::string& srcIP);
    void detectSYN(const std::string& srcIP, const std::string& dstIP, int dstPort);

public:
    Sniffer(const std::string& iface, int bytes, JSONLogger& logger);
    ~Sniffer();

    void startSniffing();
};

#endif