#ifndef SCAN_H
#define SCAN_H

#include <vector>

int get_network_interface_info(std::string &ip_addr, std::string &netmask, std::string &mac);
int get_host_in_range(std::string ip_addr, std::string netmask, std::vector<std::string> &candidates);
int scan_devices(std::string ip_addr, std::string mac_addr, std::vector<std::pair<std::string, std::string>> &answered_list, int timeout);
void print_devices(std::vector<std::pair<std::string, std::string>> &list);

#endif
