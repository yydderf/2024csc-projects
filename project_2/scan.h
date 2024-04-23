#ifndef SCAN_H
#define SCAN_H

int get_network_interface_info(char *ip_addr, char *netmask, char *mac);
std::tuple<std::string, std::string, std::string, std::string> scan_devices();
void print_devices();

#endif
