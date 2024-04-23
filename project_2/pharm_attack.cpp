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
#include "scan.h"
#include "pharm_attack.h"


int main()
{
    std::string sender_mac, target_mac;
    std::string sender_ip = "192.168.0.19";
    std::string netmask = "255.255.255.0";
    std::string ifname = "wlp3s0";

    std::vector<std::string> candidates;
    std::vector<std::pair<std::string, std::string>> answered_list;

    get_host_in_range(sender_ip, netmask, candidates);

    ARPOperator arp_operator(sender_ip, ifname);

    arp_operator.prepare_broadcast();
    for (auto candidate : candidates) {
        arp_operator.set_target(candidate, target_mac);
        arp_operator.send();
    }

    arp_operator.clear_buffer();
    arp_operator.set_timeout(0, 100);
    int nbytes;
    std::string host_ip, host_mac;

    std::cout << "Available devices" << std::endl;
    std::cout << "---------------------------------" << std::endl;
    std::cout << "IP\t\tMAC\t\t" << std::endl;
    std::cout << "---------------------------------" << std::endl;

    while (true) {
        nbytes = arp_operator.recv();
        if (nbytes < 0) {
            if (errno == EAGAIN || errno == EWOULDBLOCK) {
                // timeout
                break;
            } else {
                perror("arp_operator.recv() failed");
                exit(EXIT_FAILURE);
            }
        } else if (arp_operator.get_candidate_response(host_ip, host_mac)) {
            std::cout << host_ip << "\t" << host_mac << std::endl;
            answered_list.push_back(std::make_pair(host_ip, host_mac));
        }
    }

    // send_packet(sock, ifindex, sender_ip, sender_mac, target_ip, target_mac);

    return 0;
}

void print_devices(std::vector<std::pair<std::string, std::string>> &answered_list)
{
    for (std::pair<std::string, std::string> addr_pair : answered_list) {
        std::cout << addr_pair.first << " " << addr_pair.second << std::endl;
    }
}
