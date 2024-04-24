#include <iostream>
#include <string>
#include <cstring>
#include <cerrno>
#include <vector>
#include <cstdlib>
#include <fstream>
#include <sstream>

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

#include <dirent.h>

#include "scan.h"

// reference: https://github.com/ML-Cai/ARPSpoofing/blob/master/main.cpp#L210
int get_network_interface_info(std::string &local_ip, std::string &netmask, std::string &local_mac, std::string &if_name)
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

        if_name = std::string(entry->ifa_name);

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

std::string get_gateway(std::string ifname)
{
    std::ifstream route_file("/proc/net/route");
    if (!route_file.is_open()) {
        std::cerr << "Failed to open /proc/net/route" << std::endl;
        exit(EXIT_FAILURE);
    }

    std::string line;
    while (std::getline(route_file, line)) {
        std::string iface;
        unsigned long dest;
        unsigned long gateway;
        int flags;

        std::istringstream iss(line);
        if (!(iss >> iface >> std::hex >> dest >> std::hex >> gateway >> std::dec >> flags)) {
            continue;
        }
        if (iface != ifname) {
            continue;
        }

        if (dest == 0 && gateway != 0) {
            // Found default gateway
            route_file.close();
            struct in_addr addr;
            addr.s_addr = gateway;
            return inet_ntoa(addr);
        }
    }

    route_file.close();
    return "";
}
