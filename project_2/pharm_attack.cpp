#include <iostream>
#include <vector>
#include <string>
#include <cstring>
#include <cerrno>
#include <cstdlib>
#include <unistd.h>
#include <arpa/inet.h>
#include <net/if.h>
#include <net/ethernet.h>
#include <netinet/ether.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/time.h>

#include <linux/if_packet.h>
#include "arp.h"
#include "pharm_attack.h"


int main()
{
    std::string sender_mac, target_mac;
    std::string sender_ip = "192.168.0.19", target_ip = "192.168.0.1";
    std::string ifname = "wlp3s0";

    ARPOperator arp_operator(sender_ip, ifname);

    arp_operator.prepare_broadcast();
    arp_operator.set_target(target_ip, target_mac);
    arp_operator.send();

    // send_packet(sock, ifindex, sender_ip, sender_mac, target_ip, target_mac);

    return 0;
}

void print_devices(std::vector<std::pair<std::string, std::string>> &answered_list)
{
    for (std::pair<std::string, std::string> addr_pair : answered_list) {
        std::cout << addr_pair.first << " " << addr_pair.second << std::endl;
    }
}
