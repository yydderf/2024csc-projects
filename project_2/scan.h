#ifndef SCAN_H
#define SCAN_H

#include <vector>

int get_network_interface_info(std::string &ip_addr, std::string &netmask, std::string &mac, std::string &ifname);
int get_host_in_range(std::string ip_addr, std::string netmask, std::vector<std::string> &candidates);

#endif
