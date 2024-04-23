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

#include "arp.h"

int send_arp_broadcast(int sockfd, std::string ip_addr)
{
    std::string broadcast_mac_str = "ff:ff:ff:ff:ff:ff";
    struct arp_header arp_request;
    struct in_addr local_ip;
    struct sockaddr_in dest;

    inet_aton(ip_addr.c_str(), &local_ip);

    memset(&arp_request, 0, sizeof(arp_header));

    arp_request.htype  = htons(1);
    arp_request.ptype  = htons(ETH_P_IP);
    arp_request.hlen   = 6;
    arp_request.plen   = 4;
    arp_request.opcode = htons(1);
    memcpy(arp_request.target_mac, (void *)ether_aton(broadcast_mac_str.c_str()), 6);
    arp_request.target_ip = local_ip.s_addr;

    memset(&dest, 0, sizeof(dest));
    dest.sin_family = AF_INET;
    dest.sin_addr.s_addr = htonl(INADDR_BROADCAST);

    return sendto(sockfd, &arp_request, sizeof(arp_request), 0, (struct sockaddr *)&dest, sizeof(dest));
}

int recv_arp_responses(int sockfd, std::vector<std::pair<std::string, std::string>> &answered_list, int timeout)
{
    struct timeval tv;
    tv.tv_sec = timeout;
    tv.tv_usec = 0;
    if (setsockopt(sockfd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv)) < 0) {
        perror("setsockopt() failed");
        close(sockfd);
        exit(EXIT_FAILURE);
    }

    while (true) {
        struct arp_header arp_response;
        ssize_t nbytes = recv(sockfd, &arp_response, sizeof(arp_response), 0);
        if (nbytes < 0) {
            if (errno == EAGAIN || errno == EWOULDBLOCK) {
                // timeout
                break;
            } else {
                perror("recv() failed");
                close(sockfd);
                exit(EXIT_FAILURE);
            }
        } else if (nbytes >= sizeof(arp_response)) {
            char sender_ip[INET_ADDRSTRLEN];
            char sender_mac[18];

            inet_ntop(AF_INET, &(arp_response.sender_ip), sender_ip, INET_ADDRSTRLEN);
            sprintf(sender_mac, "%02x:%02x:%02x:%02x:%02x:%02x",
                    arp_response.sender_mac[0], arp_response.sender_mac[1],
                    arp_response.sender_mac[2], arp_response.sender_mac[3],
                    arp_response.sender_mac[4], arp_response.sender_mac[5]);
            answered_list.push_back(std::make_pair(std::string(sender_ip), std::string(sender_mac)));
        }
    }

    return 0;
}
