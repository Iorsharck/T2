#include "sniffer.h"

#include <iostream>
#include <unistd.h>
#include <cstring>
#include <sys/socket.h>
#include <linux/if_packet.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <net/ethernet.h>
#include <arpa/inet.h>
#include <net/if.h>
#include <sys/ioctl.h>

using json = nlohmann::json;

Sniffer::Sniffer(const std::string& iface,int bytes,JSONLogger& log)
: interfaceName(iface),captureBytes(bytes),logger(log)
{
    rawSocket = socket(AF_PACKET,SOCK_RAW,htons(ETH_P_ALL));

    if(rawSocket < 0)
        throw std::runtime_error("Cannot create RAW socket");
}

Sniffer::~Sniffer()
{
    close(rawSocket);
}

void Sniffer::detectARP(const std::string& srcIP)
{
    arpCounter[srcIP]++;

    if(arpCounter[srcIP] > 20)
    {
        json alert={
            {"type","alert"},
            {"event","arp_scan"},
            {"source_ip",srcIP}
        };

        logger.logJSON(alert.dump());

        arpCounter[srcIP]=0;
    }
}

void Sniffer::detectSYN(const std::string& srcIP,const std::string& dstIP,int port)
{
    auto& t = synTracker[srcIP];

    t.dstIPs.insert(dstIP);
    t.dstPorts.insert(port);

    if(t.dstPorts.size() > 10)
    {
        json alert={
            {"type","event"},
            {"event","syn_port_scan"},
            {"source_ip",srcIP}
        };

        logger.logJSON(alert.dump());

        t.dstPorts.clear();
    }

    if(t.dstIPs.size() > 10)
    {
        json alert={
            {"type","anomaly"},
            {"alert","syn_network_scan"},
            {"source_ip",srcIP}
        };

        logger.logJSON(alert.dump());

        t.dstIPs.clear();
    }
}

void Sniffer::processPacket(unsigned char* buffer,int size)
{
    struct ethhdr *eth = (struct ethhdr*)buffer;

    if(ntohs(eth->h_proto) == ETH_P_ARP)
    {
        std::cout<<"ARP detected\n";

        json log={
            {"type","packet"},
            {"protocol","ARP"}
        };

        logger.logJSON(log.dump());

        detectARP("unknown");
    }

    if(ntohs(eth->h_proto)==ETH_P_IP)
    {
        struct iphdr *iph=(struct iphdr*)(buffer+sizeof(struct ethhdr));

        if(iph->protocol==IPPROTO_TCP)
        {
            struct tcphdr *tcph=(struct tcphdr*)
                (buffer+sizeof(struct ethhdr)+iph->ihl*4);

            if(tcph->syn && !tcph->ack)
            {
                std::string src=inet_ntoa(*(in_addr*)&iph->saddr);
                std::string dst=inet_ntoa(*(in_addr*)&iph->daddr);
                int port=ntohs(tcph->dest);

                std::cout<<"SYN "<<src<<" -> "<<dst<<":"<<port<<"\n";

                json log={
                    {"type","packet"},
                    {"protocol","TCP_SYN"},
                    {"src_ip",src},
                    {"dst_ip",dst},
                    {"dst_port",port}
                };

                logger.logJSON(log.dump());

                detectSYN(src,dst,port);
            }
        }
    }
}

void Sniffer::startSniffing()
{
    unsigned char buffer[65536];

    while(true)
    {
        int dataSize=recvfrom(rawSocket,buffer,sizeof(buffer),0,NULL,NULL);

        if(dataSize < 0)
        {
            std::cerr<<"Packet receive error\n";
            continue;
        }

        processPacket(buffer,dataSize);
    }
}

