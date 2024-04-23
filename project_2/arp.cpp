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

ARPOperator::ARPOperator(std::string ip, std::string &ifname)
{
    struct ifreq ifr;
    ether_req = (struct ethhdr *)buffer;
    ether_resp = (struct ethhdr *)buffer;
    arp_req = (struct arp_header *)(buffer + ETH2_HEADER_LEN);
    arp_resp = (struct arp_header *)(buffer + ETH2_HEADER_LEN);
    ip_addr = ip;

    // use ioctl to retrieve the iterface's information
    // we first get the ifindex
    int tmp_sock = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
    if (tmp_sock == -1) {
            perror("socket():");
            exit(1);
    }
    strcpy(ifr.ifr_name, ifname.c_str());

    if (ioctl(tmp_sock, SIOCGIFINDEX, &ifr) == -1) {
        perror("SIOCGIFINDEX");
        exit(1);
    }
    ifindex = ifr.ifr_ifindex;

    // and then we get the mac address
    if (ioctl(tmp_sock, SIOCGIFHWADDR, &ifr) == -1) {
            perror("SIOCGIFINDEX");
            exit(1);
    }
    close (tmp_sock);

    memcpy(src_mac_char, (unsigned char *)ifr.ifr_hwaddr.sa_data, 6);

    mac_char_to_string(mac_addr, ifr.ifr_hwaddr.sa_data);

    // initialize the raw socket for send and recv
    if ((raw_sock = socket(PF_PACKET, SOCK_RAW, htons(ETH_P_ALL))) < 0) {
        perror("socket() failed");
        exit(EXIT_FAILURE);
    }
}

ARPOperator::~ARPOperator()
{
    // close the raw socket when torn down
    close(raw_sock);
}

void ARPOperator::prepare_broadcast()
{
    // for broadcast
    // dst -> FF:FF:FF:FF:FF:FF
    for (int index = 0; index < 6; index++)
    {
        ether_req->h_dest[index] = (unsigned char)0xff;
        arp_req->target_mac[index] = (unsigned char)0x00;
        /* Filling the source  mac address in the header*/
        ether_req->h_source[index] = src_mac_char[index];
        arp_req->sender_mac[index] = src_mac_char[index];
        socket_address.sll_addr[index] = src_mac_char[index];
    }

    // some default values
    // can be inspected via wireshark
    socket_address.sll_family = AF_PACKET;
    socket_address.sll_protocol = htons(ETH_P_ARP);
    socket_address.sll_ifindex = ifindex;
    socket_address.sll_hatype = htons(ARPHRD_ETHER);
    socket_address.sll_pkttype = (PACKET_BROADCAST);
    socket_address.sll_halen = MAC_LENGTH;
    socket_address.sll_addr[6] = 0x00;
    socket_address.sll_addr[7] = 0x00;

    ether_req->h_proto = htons(ETH_P_ARP);

    arp_req->htype = htons(HW_TYPE);
    arp_req->ptype = htons(ETH_P_IP);
    arp_req->hlen = MAC_LENGTH;
    arp_req->plen = IPV4_LENGTH;
    set_mode(ARP_REQUEST);
    set_source(ip_addr, mac_addr);
}

int ARPOperator::send()
{
    // buffer[32] = 0x00;
    return sendto(raw_sock, buffer, 42, 0, (struct sockaddr*)&socket_address, sizeof(socket_address));
}

int ARPOperator::recv()
{
    return recvfrom(raw_sock, buffer, BUF_SIZE, 0, NULL, NULL);
}

void ARPOperator::set_mode(int mode)
{
    // set mode
    // mode == ARP_REQUEST or mode == ARP_REPLY
    arp_req->opcode = htons(mode);
}

void ARPOperator::set_source(std::string ip, std::string mac)
{
    // set ip as source
    // mac address is not written (TODO?)
    ip_string_to_uchar(src_ip_char, ip);
    
    memcpy(arp_req->sender_ip, src_ip_char, 4);
}

void ARPOperator::set_target(std::string ip, std::string mac)
{
    // set ip as target
    // mac address is not written (TODO?)
    ip_string_to_uchar(dst_ip_char, ip);

    memcpy(arp_req->target_ip, dst_ip_char, 4);
}

void ARPOperator::set_timeout(int sec, int usec)
{
    struct timeval timeout;
    timeout.tv_sec = 5; // Timeout of 5 seconds
    timeout.tv_usec = 0;
    if (setsockopt(raw_sock, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout)) < 0) {
        perror("setsockopt() failed");
        close(raw_sock);
        exit(EXIT_FAILURE);
    }
}

void ARPOperator::clear_buffer()
{
    memset(buffer, 0x00, BUF_SIZE);
}

int ARPOperator::get_candidate_response(std::string &ip, std::string &mac)
{
    if (htons(ether_resp->h_proto) == PROTO_ARP) {
        ipv4_uchar_to_string(ip, arp_resp->sender_ip);
        mac_char_to_string(mac, (char*)arp_resp->sender_mac);
        return 1;
    }
    return 0;
}

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

void ipv4_uchar_to_string(std::string &target, unsigned char *ip_addr)
{
    std::stringstream ss;
    for (int i = 0; i < 4; i++) {
        ss << static_cast<int>(ip_addr[i] & 0xFF);
        if (i < 3) ss << ".";
    }
    target = ss.str();
}
