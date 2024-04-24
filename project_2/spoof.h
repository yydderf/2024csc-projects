#ifndef SPOOF_H
#define SPOOF_H

#include <map>

#include "arp.h"

class SpoofOperator {
    ARPOperator *arp_operator;
    std::string source_ip;
    std::string gateway_ip;
    std::map<std::string, std::string> *ip2mac_map;
public:
    SpoofOperator(ARPOperator *arp_operator, std::string gateway_ip, std::map<std::string, std::string> *ip2mac_map);
    int attack(std::string target_ip);
    int restore(std::string target_ip);
};

int set_ip_forwarding(int toggle);

#endif
