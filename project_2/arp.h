#ifndef ARP_H
#define ARP_H

#define PROTO_ARP 0x0806
#define ETH2_HEADER_LEN 14
#define HW_TYPE 1
#define PROTOCOL_TYPE 0x800
#define MAC_LENGTH 6
#define IPV4_LENGTH 4
#define ARP_REQUEST 0x01
#define ARP_REPLY 0x02
#define BUF_SIZE 60

struct arp_header {
    unsigned short htype;    /* Hardware Type           */
    unsigned short ptype;    /* Protocol Type           */
    unsigned char hlen;        /* Hardware Address Length */
    unsigned char plen;        /* Protocol Address Length */
    unsigned short opcode;     /* Operation Code          */
    unsigned char sender_mac[MAC_LENGTH];      /* Sender hardware address */
    unsigned char sender_ip[IPV4_LENGTH];      /* Sender IP address       */
    unsigned char target_mac[MAC_LENGTH];      /* Target hardware address */
    unsigned char target_ip[IPV4_LENGTH];      /* Target IP address       */

};

void send_packet();
void ip_string_to_uchar(std::string &str, unsigned char *target);

#endif
