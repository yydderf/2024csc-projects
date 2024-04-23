#ifndef ARP_H
#define ARP_H

struct arp_header {
    u_int16_t htype;    /* Hardware Type           */
    u_int16_t ptype;    /* Protocol Type           */
    u_char   hlen;        /* Hardware Address Length */
    u_char   plen;        /* Protocol Address Length */
    uint16_t opcode;     /* Operation Code          */
    uint8_t  sender_mac[6];      /* Sender hardware address */
    uint32_t sender_ip;      /* Sender IP address       */
    uint8_t  target_mac[6];      /* Target hardware address */
    uint32_t target_ip;      /* Target IP address       */

};

int send_arp_broadcast(int sockfd, std::string sender_ip, std::string target_ip);
int recv_arp_responses(int sockfd, std::vector<std::pair<std::string, std::string>> &answered_list, int timeout);

#endif
