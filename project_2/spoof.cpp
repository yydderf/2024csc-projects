#include <string>
#include <sys/socket.h>
#include <linux/if_packet.h>
#include <net/ethernet.h>

#include "spoof.h"
#include "arp.h"

SpoofOperator::SpoofOperator(ARPOperator *arp_operator, std::string gateway_ip, std::map<std::string, std::string> *ip2mac_map)
{
    this->ip2mac_map = ip2mac_map;
    this->arp_operator = arp_operator;
    this->gateway_ip = gateway_ip;
}

int SpoofOperator::attack(std::string target_ip)
{
    // set opcode = 2
    arp_operator->set_mode(ARP_REPLY);
    // set pdst = target_ip
    
    // set hwdst = target_mac
    // set psrc = spoof_ip
    // send packet
    return 0;
}

int SpoofOperator::restore(std::string target_ip)
{
    return 0;
}
