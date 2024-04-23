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
#include "arp.h"

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
        if(addr_family == AF_INET){
            if(entry->ifa_addr != nullptr){
                char buffer[INET_ADDRSTRLEN] = {0, };
                inet_ntop(
                    addr_family,
                    &((struct sockaddr_in*)(entry->ifa_addr))->sin_addr,
                    buffer,
                    INET_ADDRSTRLEN
                );

                local_ip.assign(buffer, INET_ADDRSTRLEN);
            }

            if(entry->ifa_netmask != nullptr){
                char buffer[INET_ADDRSTRLEN] = {0, };
                inet_ntop(
                    addr_family,
                    &((struct sockaddr_in*)(entry->ifa_netmask))->sin_addr,
                    buffer,
                    INET_ADDRSTRLEN
                );

                netmask.assign(buffer, INET_ADDRSTRLEN);
            }
        }
        if (addr_family == AF_PACKET) {
            char buffer[18];
            if (entry->ifa_addr != nullptr) {
                struct sockaddr_ll *s = (struct sockaddr_ll*)entry->ifa_addr;
                buffer[6] = 0;
                sprintf(buffer, "%02x:%02x:%02x:%02x:%02x:%02x",
                        s->sll_addr[0], s->sll_addr[1], s->sll_addr[2],
                        s->sll_addr[3], s->sll_addr[4], s->sll_addr[5]);
            }
            local_mac.assign(buffer, 18);
        }
    }

    freeifaddrs(ptr_ifaddrs);
    return EX_OK;
}

int scan_devices(std::string ip_addr, std::string mac_addr, 
        std::vector<std::pair<std::string, std::string>> &answered_list, int timeout)
{
    int sockfd = socket(AF_INET, SOCK_RAW, IPPROTO_RAW);
    if (sockfd < 0) {
        perror("socket() failed");
        exit(EXIT_FAILURE);
    }

    int optval = 1;
    if (setsockopt(sockfd, SOL_SOCKET, SO_BROADCAST, &optval, sizeof(optval)) < 0) {
        perror("setsocketopt() failed");
        close(sockfd);
        exit(EXIT_FAILURE);
    }

    if (send_arp_broadcast(sockfd, ip_addr) < 0) {
        perror("send_arp_broadcast() failed");
        close(sockfd);
        exit(EXIT_FAILURE);
    }

    recv_arp_responses(sockfd, answered_list, timeout);

    close(sockfd);

    return 0;
}
