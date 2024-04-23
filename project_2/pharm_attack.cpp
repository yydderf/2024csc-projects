#include <iostream>

#include "scan.h"
#include "pharm_attack.h"


int main()
{
    std::cout << "Test" << std::endl;
    std::string ip_addr, netmask, mac_addr;
    get_network_interface_info(ip_addr, netmask, mac_addr);
    std::cout << ip_addr << " " << netmask << " " << mac_addr << std::endl;

    std::vector<std::pair<std::string, std::string>> answered_list;
    scan_devices(ip_addr, mac_addr, answered_list, 5);

    print_devices(answered_list);

    return 0;
}

void print_devices(std::vector<std::pair<std::string, std::string>> &answered_list)
{
    for (std::pair<std::string, std::string> addr_pair : answered_list) {
        std::cout << addr_pair.first << " " << addr_pair.second << std::endl;
    }
}
