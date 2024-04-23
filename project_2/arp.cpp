#include <iostream>
#include <vector>
#include <string>
#include <cstring>
#include <cerrno>
#include <sstream>
#include <iomanip>
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

void ip_string_to_uchar(unsigned char *target, std::string &str_ip)
{
    struct in_addr addr;

    if (inet_aton(str_ip.c_str(), &addr) == 0) {
        std::cerr << "Invalid IP address" << std::endl;
        exit(EXIT_FAILURE);
    }
    memcpy(target, &addr.s_addr, sizeof(addr.s_addr));
}

void mac_char_to_string(std::string &target, char *mac_addr)
{
    std::stringstream ss;
    ss << std::hex << std::setfill('0');
    for (int i = 0; i < 6; i++) {
        ss << std::setw(2) << static_cast<int>(mac_addr[i] & 0xFF);
        if (i < 5) ss << ":";
    }
    target = ss.str();
}

void ipv4_char_to_string(std::string &target, unsigned char *ip_addr)
{
    std::stringstream ss;
    for (int i = 0; i < 4; i++) {
        ss << static_cast<int>(ip_addr[i] & 0xFF);
        if (i < 3) ss << ".";
    }
    target = ss.str();
}

void send_packet(int raw_sock, int ifindex,
        std::string sender_ip, std::string sender_mac,
        std::string target_ip, std::string target_mac)
{
    unsigned char buffer[BUF_SIZE];
    // struct ifreq ifr;
    struct ethhdr *send_req = (struct ethhdr *)buffer;
    struct ethhdr *rcv_resp= (struct ethhdr *)buffer;
    struct arp_header *arp_req = (struct arp_header *)(buffer+ETH2_HEADER_LEN);
    struct arp_header *arp_resp = (struct arp_header *)(buffer+ETH2_HEADER_LEN);
    struct sockaddr_ll socket_address;
    int index, ret, length=0;

    memset(buffer,0x00,60);
    /*open socket*/

    for (index = 0; index < 6; index++)
    {
        send_req->h_dest[index] = (unsigned char)0xff;
        arp_req->target_mac[index] = (unsigned char)0x00;
    }

    /*prepare sockaddr_ll*/
    socket_address.sll_family = AF_PACKET;
    socket_address.sll_protocol = htons(ETH_P_ARP);
    socket_address.sll_ifindex = ifindex;
    socket_address.sll_hatype = htons(ARPHRD_ETHER);
    socket_address.sll_pkttype = (PACKET_BROADCAST);
    socket_address.sll_halen = MAC_LENGTH;
    socket_address.sll_addr[6] = 0x00;
    socket_address.sll_addr[7] = 0x00;

    /* Setting protocol of the packet */
    send_req->h_proto = htons(ETH_P_ARP);
    memcpy(send_req->h_source, (void *)ether_aton(sender_mac.c_str()), 6);
    memcpy(arp_req->sender_mac, (void *)ether_aton(sender_mac.c_str()), 6);
    memcpy(socket_address.sll_addr, (void *)ether_aton(sender_mac.c_str()), 6);

    /* Creating ARP request */
    arp_req->htype = htons(HW_TYPE);
    arp_req->ptype = htons(ETH_P_IP);
    arp_req->hlen = MAC_LENGTH;
    arp_req->plen = IPV4_LENGTH;
    arp_req->opcode = htons(ARP_REQUEST);

    ip_string_to_uchar(arp_req->sender_ip, sender_ip);
    ip_string_to_uchar(arp_req->target_ip, target_ip);

    buffer[32]=0x00;
    // send
    ret = sendto(raw_sock, buffer, 42, 0, (struct  sockaddr*)&socket_address, sizeof(socket_address));
    if (ret == -1) {
        perror("sendto():");
        exit(EXIT_FAILURE);
    }

    memset(buffer,0x00,60);
    while(1) {
        length = recvfrom(raw_sock, buffer, BUF_SIZE, 0, NULL, NULL);
        if (length == -1) {
            perror("recvfrom():");
            exit(EXIT_FAILURE);
        } if(htons(rcv_resp->h_proto) == PROTO_ARP) {
            std::string ip_str;
            std::string mac_str;
            ipv4_char_to_string(ip_str, arp_resp->sender_ip);
            mac_char_to_string(mac_str, (char*)arp_resp->sender_mac);
            std::cout << ip_str << " " << mac_str << std::endl;

            break;
        }
    }
}
