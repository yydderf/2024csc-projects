#include <arpa/inet.h>
#include <cerrno>
#include <ifaddrs.h>
#include <iostream>
#include <net/if.h>
#include <net/ethernet.h>
#include <string>
#include <string.h>
#include <sysexits.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <linux/if_packet.h>
#include <iomanip>

#include "scan.h"

// reference: https://github.com/ML-Cai/ARPSpoofing/blob/master/main.cpp#L210
int get_network_interface_info(char *local_ip, char *netmask, char *local_mac)
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
                // char buffer[INET_ADDRSTRLEN] = {0, };
                inet_ntop(
                    addr_family,
                    &((struct sockaddr_in*)(entry->ifa_addr))->sin_addr,
                    local_ip,
                    INET_ADDRSTRLEN
                );

                ip_hr = std::string(local_ip);
            }

            if(entry->ifa_netmask != nullptr){
                // char buffer[INET_ADDRSTRLEN] = {0, };
                inet_ntop(
                    addr_family,
                    &((struct sockaddr_in*)(entry->ifa_netmask))->sin_addr,
                    netmask,
                    INET_ADDRSTRLEN
                );

                netmask_hr = std::string(netmask);
            }
            std::cout << ip_hr << " " << netmask_hr << std::endl;
        }
        if (addr_family == AF_PACKET) {
            if (entry->ifa_addr != nullptr) {
                struct sockaddr_ll *s = (struct sockaddr_ll*)entry->ifa_addr;
                memcpy(local_mac, s->sll_addr, 8);
                local_mac[6] = 0;
                sprintf(local_mac, "%02x:%02x:%02x:%02x:%02x:%02x",
                        s->sll_addr[0], s->sll_addr[1], s->sll_addr[2],
                        s->sll_addr[3], s->sll_addr[4], s->sll_addr[5]);
            }
            std::cout << local_mac << std::endl;
        }
    }

    freeifaddrs(ptr_ifaddrs);
    return EX_OK;
}
