#ifndef FILTER_H
#define FILTER_H

#define NF_DROP 0
#define NF_ACCEPT 1

static int callback(struct nfq_q_handle *qh, struct nfgenmsg *nfmsg,
        struct nfq_data *nfa, void *data);
void extractHttpInfo(const unsigned char* payload, int payloadSize);

class FilterOperator {
    struct nfq_handle *h;
    struct nfq_q_handle *qh;
    struct nfnl_handle *nh;
    int fd;
    char buf[4096] __attribute__ ((aligned));

public:
    FilterOperator();
    ~FilterOperator();
    void proc_http();
    void proc_dns();
    void handle_packet(int rv);
    void set_timeout(int sec, int usec);
    int receive();
};

#endif
