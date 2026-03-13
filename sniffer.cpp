#include "sniffer.h"

#include <iostream>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <net/ethernet.h>
#include <arpa/inet.h>
#include <sstream>

using json = nlohmann::json;

Sniffer::Sniffer(const std::string& iface, int bytes, JSONLogger& log)
: interfaceName(iface), captureBytes(bytes), logger(log)
{
    handle = nullptr;
    lastReset = std::chrono::steady_clock::now();
}

Sniffer::~Sniffer()
{
    if(handle)
        pcap_close(handle);
}

void Sniffer::packetHandler(u_char *user,
                            const struct pcap_pkthdr *header,
                            const u_char *packet)
{
    Sniffer* sniffer = reinterpret_cast<Sniffer*>(user);
    sniffer->processPacket(header, packet);
}

void Sniffer::detectARP(const std::string& srcIP)
{
    arpCounter[srcIP]++;

    if(arpCounter[srcIP] > 20)
    {
        json alert = {
            {"type","alert"},
            {"event","arp_scan"},
            {"source_ip",srcIP},
            {"count",arpCounter[srcIP]}
        };

        logger.logJSON(alert.dump());
        arpCounter[srcIP] = 0;
    }
}

void Sniffer::detectSYN(const std::string& srcIP,
                        const std::string& dstIP,
                        int dstPort)
{
    auto& tracker = synTracker[srcIP];

    tracker.dstIPs.insert(dstIP);
    tracker.dstPorts.insert(dstPort);
    tracker.lastSeen = std::chrono::steady_clock::now();

    if(tracker.dstPorts.size() > 10)
    {
        json alert = {
            {"type","alert"},
            {"event","syn_port_scan"},
            {"source_ip",srcIP},
            {"unique_ports",tracker.dstPorts.size()}
        };

        logger.logJSON(alert.dump());

        tracker.dstPorts.clear();
    }

    if(tracker.dstIPs.size() > 10)
    {
        json alert = {
            {"type","alert"},
            {"event","syn_network_scan"},
            {"source_ip",srcIP},
            {"unique_hosts",tracker.dstIPs.size()}
        };

        logger.logJSON(alert.dump());

        tracker.dstIPs.clear();
    }
}

void Sniffer::processPacket(const struct pcap_pkthdr *header,
                            const u_char *packet)
{
    const struct ether_header *eth =
        (struct ether_header *) packet;

    if(ntohs(eth->ether_type) == ETHERTYPE_ARP)
    {
        std::cout << "[ARP] packet detected\n";

        json log = {
            {"type","packet"},
            {"protocol","ARP"}
        };

        logger.logJSON(log.dump());
        detectARP("unknown");
    }

    if(ntohs(eth->ether_type) == ETHERTYPE_IP)
    {
        const struct ip* iphdr =
            (struct ip*)(packet + sizeof(struct ether_header));

        if(iphdr->ip_p == IPPROTO_TCP)
        {
            const struct tcphdr* tcph =
                (struct tcphdr*)((u_char*)iphdr + iphdr->ip_hl*4);

            if(tcph->syn && !tcph->ack)
            {
                std::string srcIP = inet_ntoa(iphdr->ip_src);
                std::string dstIP = inet_ntoa(iphdr->ip_dst);
                int dstPort = ntohs(tcph->dest);

                std::cout << "[TCP SYN] "
                          << srcIP << " -> "
                          << dstIP << ":"
                          << dstPort << std::endl;

                json log = {
                    {"type","packet"},
                    {"protocol","TCP_SYN"},
                    {"src_ip",srcIP},
                    {"dst_ip",dstIP},
                    {"dst_port",dstPort}
                };

                logger.logJSON(log.dump());

                detectSYN(srcIP, dstIP, dstPort);
            }
        }
    }
}

void Sniffer::startSniffing()
{
    char errbuf[PCAP_ERRBUF_SIZE];

    handle = pcap_open_live(interfaceName.c_str(),
                            BUFSIZ,
                            1,
                            1000,
                            errbuf);

    if(handle == nullptr)
    {
        std::cerr << "Error opening interface: "
                  << errbuf << std::endl;
        return;
    }

    struct bpf_program fp;
    std::string filter_exp =
        "arp or (tcp[tcpflags] & tcp-syn != 0)";

    if(pcap_compile(handle, &fp,
                    filter_exp.c_str(),
                    0, PCAP_NETMASK_UNKNOWN) == -1)
    {
        std::cerr << "BPF compile error\n";
        return;
    }

    if(pcap_setfilter(handle, &fp) == -1)
    {
        std::cerr << "BPF set error\n";
        return;
    }

    std::cout << "Sniffer started on "
              << interfaceName << std::endl;

    pcap_loop(handle, 0, packetHandler,
              reinterpret_cast<u_char*>(this));
}