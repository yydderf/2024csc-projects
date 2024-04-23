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

void mac_char_to_string(std::string &target, char *mac_addr);
void ipv4_uchar_to_string(std::string &target, unsigned char *ip_addr);
void ip_string_to_uchar(unsigned char *target, std::string &str_ip);

class ARPOperator {
    int raw_sock;
    int ifindex;
    std::string ip_addr;
    std::string mac_addr;
    struct ethhdr *ether_req;
    struct ethhdr *ether_resp;
    struct arp_header *arp_req;
    struct arp_header *arp_resp;
    struct sockaddr_ll socket_address;
    unsigned char buffer[BUF_SIZE];
    unsigned char src_ip_char[4];
    unsigned char src_mac_char[6];
    unsigned char dst_ip_char[4];
    unsigned char dst_mac_char[6];
public:
    ARPOperator(std::string sender_ip, std::string &ifname);
    ~ARPOperator();
    void prepare_broadcast();
    int send();
    int recv();
    void clear_buffer();
    void set_mode(int mode);
    void set_source(std::string ip, std::string mac);
    void set_target(std::string ip, std::string mac);
    void set_timeout(int sec, int usec);
    int get_candidate_response(std::string &ip, std::string &mac);
};

#endif
