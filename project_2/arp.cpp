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

/**
 * @param ip local ip address
 * @param ifname target local network's network interface name
 */
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

    // initialize socket address
    prepare_socket_address();

    // initialize arp / ether header values
    prepare_header_values();
}

ARPOperator::~ARPOperator()
{
    // close the raw socket when torn down
    close(raw_sock);
}

/**
 * Prepare for socket address
 * Only required in the initialization of ARPOperator
 */
void ARPOperator::prepare_socket_address()
{
    socket_address.sll_family = AF_PACKET;
    socket_address.sll_protocol = htons(ETH_P_ARP);
    socket_address.sll_ifindex = ifindex;
    socket_address.sll_hatype = htons(ARPHRD_ETHER);
    socket_address.sll_halen = MAC_LENGTH;
    socket_address.sll_addr[6] = 0x00;
    socket_address.sll_addr[7] = 0x00;
}

/**
 * Write the values to the ether frame headers
 * Called after the buffer is cleared
 */
void ARPOperator::prepare_header_values()
{
    ether_req->h_proto = htons(ETH_P_ARP);

    arp_req->htype = htons(HW_TYPE);
    arp_req->ptype = htons(ETH_P_IP);
    arp_req->hlen = MAC_LENGTH;
    arp_req->plen = IPV4_LENGTH;
}

/**
 * Prepare for broadcast
 * (network neighbors discovery)
 * mac_dst -> FF:FF:FF:FF:FF:FF
 * mac_src -> local_mac_addr
 */
void ARPOperator::prepare_broadcast()
{
    // for broadcast
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
    socket_address.sll_pkttype = (PACKET_BROADCAST);

    set_mode(ARP_REQUEST);
    set_source(ip_addr, mac_addr);
}

/**
 * Prepare for unicast
 * (send reply packet to targets)
 */
void ARPOperator::prepare_unicast()
{
    socket_address.sll_pkttype = (PACKET_OTHERHOST);

    set_mode(ARP_REPLY);
}

/**
 * Send the buffer
 */
int ARPOperator::send()
{
    // buffer[32] = 0x00;
    return sendto(raw_sock, buffer, 42, 0, (struct sockaddr*)&socket_address, sizeof(socket_address));
}

/**
 * Recv ARP packets and write to buffer
 */
int ARPOperator::recv()
{
    return recvfrom(raw_sock, buffer, BUF_SIZE, 0, NULL, NULL);
}

/**
 * Set ARPOperator's mode
 * ARP_REQUEST for arp request
 * ARP_REPLY for arp reply
 */
void ARPOperator::set_mode(int mode)
{
    // set mode
    // mode == ARP_REQUEST or mode == ARP_REPLY
    arp_req->opcode = htons(mode);
}

void ARPOperator::set_ether_source(std::string mac)
{
    memcpy(ether_req->h_source, (unsigned char *)ether_aton(mac.c_str()), 6);
}

void ARPOperator::set_ether_target(std::string mac)
{
    memcpy(ether_req->h_dest, (unsigned char *)ether_aton(mac.c_str()), 6);
}

void ARPOperator::set_source(std::string ip, std::string mac)
{
    // set ip as source
    // mac address is not written (TODO?)
    ip_string_to_uchar(src_ip_char, ip);
    
    memcpy(arp_req->sender_ip, src_ip_char, 4);
    memcpy(arp_req->sender_mac, (unsigned char *)ether_aton(mac.c_str()), 6);
}

void ARPOperator::set_target(std::string ip, std::string mac)
{
    // set ip as target
    // mac address is not written (TODO?)
    ip_string_to_uchar(dst_ip_char, ip);

    memcpy(arp_req->target_ip, dst_ip_char, 4);
    memcpy(arp_req->target_mac, (unsigned char *)ether_aton(mac.c_str()), 6);
}

void ARPOperator::set_timeout(int sec, int usec)
{
    struct timeval timeout;
    timeout.tv_sec = sec; // Timeout of 5 seconds
    timeout.tv_usec = usec;
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

std::string ARPOperator::get_local_ip()
{
    return ip_addr;
}

std::string ARPOperator::get_local_mac()
{
    return mac_addr;
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

void ARPOperator::list_frame_info()
{
    std::string ether_hdest, ether_hsource;
    std::string arp_sender_mac, arp_sender_ip;
    std::string arp_target_mac, arp_target_ip;
    mac_char_to_string(ether_hdest, (char*)ether_req->h_dest);
    mac_char_to_string(ether_hsource, (char*)ether_req->h_source);
    mac_char_to_string(arp_sender_mac, (char*)arp_req->sender_mac);
    mac_char_to_string(arp_target_mac, (char*)arp_req->target_mac);
    ipv4_uchar_to_string(arp_sender_ip, arp_req->sender_ip);
    ipv4_uchar_to_string(arp_target_ip, arp_req->target_ip);

    std::cout << "ether: " << ether_hsource << " -> " << ether_hdest << std::endl;
    std::cout << "arp-mac: " << arp_sender_mac << " -> " << arp_target_mac << std::endl;
    std::cout << "arp-ip : " << arp_sender_ip << " -> " << arp_target_ip << std::endl;
    std::cout << "-----------------------------" << std::endl;
}
