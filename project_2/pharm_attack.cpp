#include <iostream>

#include "scan.h"

int main()
{
    std::cout << "Test" << std::endl;
    char ip_addr[256] = {0};
    char netmask[256] = {0};
    char mac_addr[8] = {0};
    get_network_interface_info(ip_addr, netmask, mac_addr);

    return 0;
}

