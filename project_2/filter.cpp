#include <cstdlib>
#include <iostream>

#include <arpa/inet.h>
#include <unistd.h>
#include <fcntl.h>

#include <linux/netfilter.h>		
#include <libnetfilter_queue/libnetfilter_queue.h>

#include "filter.h"

FilterOperator::FilterOperator()
{   
    // Open library handle
    if (!(h = nfq_open())) {
        std::cerr << "Error in nfq_open()" << std::endl;
        exit(EXIT_FAILURE);
    }

    // Unbind existing nf_queue handler (if any)
    if (nfq_unbind_pf(h, AF_INET) < 0) {
        std::cerr << "Error in nfq_unbind_pf()" << std::endl;
        exit(EXIT_FAILURE);
    }

    // Bind nfnetlink_queue as nf_queue handler of AF_INET
    if (nfq_bind_pf(h, AF_INET) < 0) {
        std::cerr << "Error in nfq_bind_pf()" << std::endl;
        exit(EXIT_FAILURE);
    }

    // Install a callback on queue 0
    if (!(qh = nfq_create_queue(h,  0, &callback, NULL))) {
        std::cerr << "Error in nfq_create_queue()" << std::endl;
        exit(EXIT_FAILURE);
    }

    // Set the amount of packet data to copy to userspace
    if (nfq_set_mode(qh, NFQNL_COPY_PACKET, 0xffff) < 0) {
        std::cerr << "Can't set packet_copy mode" << std::endl;
        exit(EXIT_FAILURE);
    }

    // Get file descriptor for queue
    if ((fd = nfq_fd(h)) < 0) {
        std::cerr << "Can't get nfq_fd" << std::endl;
        exit(EXIT_FAILURE);
    }
}

FilterOperator::~FilterOperator()
{
    nfq_destroy_queue(qh);
    nfq_close(h);
}

void FilterOperator::proc_http()
{
}

void FilterOperator::proc_dns()
{
}

void FilterOperator::handle_packet(int rv)
{
    nfq_handle_packet(h, buf, rv);
}

int FilterOperator::receive()
{
    return recv(fd, buf, sizeof(buf), 0);
}

void FilterOperator::set_timeout(int sec, int usec)
{
    struct timeval timeout;
    timeout.tv_sec = sec; // Timeout of 5 seconds
    timeout.tv_usec = usec;
    if (setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout)) < 0) {
        perror("setsockopt() failed");
        close(fd);
        exit(EXIT_FAILURE);
    }
}

static int callback(struct nfq_q_handle *qh, struct nfgenmsg *nfmsg,
                    struct nfq_data *nfa, void *data)
{
    unsigned char *payload;
    int ret;
    unsigned int id = 0;
    struct nfqnl_msg_packet_hdr *ph = nfq_get_msg_packet_hdr(nfa);
    if (ph) {
        id = ntohl(ph->packet_id);
    }

    ret = nfq_get_payload(nfa, &payload);
    if (ret >= 0) {
        // Analyze the packet and determine if it's from the victim to the AP
        // Modify the packet's destination MAC address to that of the AP
        // Optionally, modify other packet fields as needed

        // Accept or drop the modified packet
        return NF_ACCEPT;
    }

    return NF_ACCEPT;
}
