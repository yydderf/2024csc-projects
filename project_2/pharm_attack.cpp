#include <iostream>

#include "arp.h"
#include "pharm_attack.h"


int main()
{
    send_packet();
}

void print_devices(std::vector<std::pair<std::string, std::string>> &answered_list)
{
    for (std::pair<std::string, std::string> addr_pair : answered_list) {
        std::cout << addr_pair.first << " " << addr_pair.second << std::endl;
    }
}
