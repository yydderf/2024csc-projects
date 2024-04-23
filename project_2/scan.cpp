#include <iostream>
#include <string>
#include <cstring>
#include <cerrno>
#include <vector>
#include <cstdlib>

#include <unistd.h>
#include <netinet/ether.h>
#include <net/if.h>
#include <net/ethernet.h>
#include <arpa/inet.h>
#include <ifaddrs.h>

#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <sysexits.h>
#include <sys/types.h>

#include <string.h>
#include <linux/if_packet.h>

#include "scan.h"

// reference: https://github.com/ML-Cai/ARPSpoofing/blob/master/main.cpp#L210
int get_network_interface_info(std::string &local_ip, std::string &netmask, std::string &local_mac)
{
    struct ifaddrs* ptr_ifaddrs = nullptr;
    struct ifaddrs* entry = nullptr;

    auto result = getifaddrs(&ptr_ifaddrs);
    if (result != 0) {
        std::cout << "`getifaddrs()` failed: " << strerror(errno) << std::endl;
        return EX_OSERR;
    }

    for(entry = ptr_ifaddrs; entry != nullptr; entry = entry->ifa_next) {
        std::string ip_hr;
        std::string netmask_hr;

        std::string if_name = std::string(entry->ifa_name);

        if (if_name == "lo") {
            continue;
        }

        sa_family_t addr_family = entry->ifa_addr->sa_family;
        if (addr_family == AF_INET){
            if (entry->ifa_addr != nullptr) {
                char buffer[INET_ADDRSTRLEN] = {0, };
                inet_ntop(
                    addr_family,
                    &((struct sockaddr_in*)(entry->ifa_addr))->sin_addr,
                    buffer,
                    INET_ADDRSTRLEN
                );

                local_ip.assign(buffer, INET_ADDRSTRLEN);
            }

            if (entry->ifa_netmask != nullptr) {
                char buffer[INET_ADDRSTRLEN] = {0, };
                inet_ntop(
                    addr_family,
                    &((struct sockaddr_in*)(entry->ifa_netmask))->sin_addr,
                    buffer,
                    INET_ADDRSTRLEN
                );

                netmask.assign(buffer, INET_ADDRSTRLEN);
            }
            break;
        }
    }

    freeifaddrs(ptr_ifaddrs);
    return EX_OK;
}

int get_host_in_range(std::string ip_addr, std::string netmask, std::vector<std::string> &candidates)
{
    struct in_addr addr;
    struct in_addr mask;
    inet_aton(ip_addr.c_str(), &addr);
    inet_aton(netmask.c_str(), &mask);

    struct in_addr network_addr;
    struct in_addr broadcast_addr;
    network_addr.s_addr = addr.s_addr & mask.s_addr;
    broadcast_addr.s_addr = addr.s_addr | ~mask.s_addr;

    struct in_addr candidate;
    for (auto i = ntohl(network_addr.s_addr) + 1; i < ntohl(broadcast_addr.s_addr); i++) {
        candidate.s_addr = htonl(i);
        candidates.push_back(inet_ntoa(candidate));
    }

    return 0;
}

// int scan_devices(std::string ip_addr, std::string mac_addr, 
//         std::vector<std::pair<std::string, std::string>> &answered_list, int timeout)
// {
//     int sockfd = socket(PF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
//     if (sockfd < 0) {
//         perror("socket() failed");
//         exit(EXIT_FAILURE);
//     }
// 
//     // int optval = 1;
//     // if (setsockopt(sockfd, SOL_SOCKET, SO_BROADCAST, &optval, sizeof(optval)) < 0) {
//     //     perror("setsocketopt() failed");
//     //     close(sockfd);
//     //     exit(EXIT_FAILURE);
//     // }
// 
//     if (send_arp_broadcast(sockfd, ip_addr, "76.12.0.32") < 0) {
//         perror("send_arp_broadcast() failed");
//         close(sockfd);
//         exit(EXIT_FAILURE);
//     }
// 
//     std::cout << "sent" << std::endl;
// 
//     recv_arp_responses(sockfd, answered_list, timeout);
// 
//     close(sockfd);
// 
//     return 0;
// }
