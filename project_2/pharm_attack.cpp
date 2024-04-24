#include <iostream>
#include <vector>
#include <string>
#include <cstring>
#include <cerrno>
#include <cstdlib>
#include <unistd.h>
#include <map>
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
#include "spoof.h"
#include "pharm_attack.h"


int main()
{
    std::string sender_mac, target_mac;
    std::string sender_ip, target_ip, netmask, ifname;
    std::string gateway_ip;
    
    // iterate through all network interfaces
    // stops if ifname != "lo"
    get_network_interface_info(sender_ip, netmask, sender_mac, ifname);
    gateway_ip = get_gateway(ifname);

    std::vector<std::string> candidates;
    std::vector<std::pair<std::string, std::string>> answered_list;
    std::map<std::string, std::string> ip2mac_map;

    // use ip and netmask to calculate all possible neighbors
    get_host_in_range(sender_ip, netmask, candidates);

    // initiation of self defined arp operator
    // used to initialize & send & recv arp packets
    ARPOperator arp_operator(sender_ip, ifname);

    // initialize broadcast for neighbor discovery
    arp_operator.prepare_broadcast();
    for (auto candidate : candidates) {
        arp_operator.set_target(candidate, target_mac);
        arp_operator.send();
    }

    // set timeout
    // don't know how to set the actual timeout window
    arp_operator.clear_buffer();
    arp_operator.set_timeout(2, 0);
    int nbytes;
    std::string host_ip, host_mac;

    // print the banner
    std::cout << "Available devices" << std::endl;
    std::cout << "---------------------------------" << std::endl;
    std::cout << "IP\t\tMAC\t\t" << std::endl;
    std::cout << "---------------------------------" << std::endl;

    // recv packets continuously until timeout
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
            ip2mac_map[host_ip] = host_mac;
        }
    }

    // choose the first target that is not the gateway
    std::map<std::string, std::string>::iterator it;
    for (it = ip2mac_map.begin(); it != ip2mac_map.end(); it++) {
        if (it->first != gateway_ip) {
            target_ip = it->first;
            target_mac = it->second;
        }
    }

    // initialize the spoof operator
    SpoofOperator spoof_operator(&arp_operator, gateway_ip, &ip2mac_map);

    std::cout << "target: " << target_ip << " " << target_mac << std::endl;

    if (set_ip_forwarding(1) < 0) {
        exit(EXIT_FAILURE);
    }

    return 0;
}
