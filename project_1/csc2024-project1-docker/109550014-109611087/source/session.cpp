#include "session.h"

#include <net/ethernet.h>
#include <net/if.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <sys/epoll.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <unistd.h>

#include <iostream>
#include <span>
#include <utility>
#include <numeric>

extern bool running;

uint16_t calculateIPChecksum(struct iphdr hdr)
{
  struct iphdr *ptr = &hdr;
  uint16_t *hdr_ptr = (uint16_t *)ptr;
  size_t hdr_len = hdr.ihl * 4;
  uint32_t checksum = 0;

  while (hdr_len > 1) {
    checksum += *hdr_ptr++;
    hdr_len -= 2;
  }

  if (hdr_len) {
    checksum += (*hdr_ptr) & htons(0xFF00);
  }

  while (checksum >> 16) {
    checksum = (checksum & 0xFFFF) + (checksum >> 16);
  }

  return ~checksum;
}

uint16_t calculateTCPChecksum(struct PseudoIPv4Header &ip_hdr, struct tcphdr tcp_hdr, const std::string &payload)
{
  int sum = 0;
  uint16_t checksum;
  uint16_t tcp_hdr_len = tcp_hdr.th_off * 4;
  uint16_t tcp_len = tcp_hdr_len + payload.size();

  sum += (ip_hdr.src >> 16) & 0xFFFF;
  sum += (ip_hdr.src) & 0xFFFF;
  sum += (ip_hdr.dst >> 16) & 0xFFFF;
  sum += (ip_hdr.dst) & 0xFFFF;
  sum += htons(ip_hdr.protocol);
  sum += htons(tcp_len);

  uint8_t *buf = (uint8_t*)malloc((tcp_hdr_len + payload.size()) * sizeof(uint8_t));
  memcpy(buf, &tcp_hdr, tcp_hdr_len);
  memcpy(buf + tcp_hdr_len, payload.c_str(), payload.size());
  uint16_t *tmp_ptr = (uint16_t*)buf;

  while (tcp_len > 1) {
    sum += *tmp_ptr++;
    tcp_len -= 2;
  }

  if (tcp_len) {
    sum += (*tmp_ptr) & htons(0xFF00);
  }

  while (sum >> 16) {
    sum = (sum >> 16) + (sum & 0xFFFF);
  }

  checksum = ~sum;
  return checksum;
}

Session::Session(const std::string& iface, ESPConfig&& cfg)
    : sock{0}, recvBuffer{}, sendBuffer{}, config{std::move(cfg)}, state{} {
  checkError(sock = socket(AF_PACKET, SOCK_DGRAM, htons(ETH_P_ALL)), "Create socket failed");
  // TODO: Setup sockaddr_ll
  sockaddr_ll addr_ll{};
  addr_ll.sll_family = AF_PACKET;
  addr_ll.sll_protocol = htons(ETH_P_ALL);
  addr_ll.sll_ifindex = if_nametoindex(iface.c_str());
  checkError(bind(sock, reinterpret_cast<sockaddr*>(&addr_ll), sizeof(sockaddr_ll)), "Bind failed");
}

Session::~Session() {
  shutdown(sock, SHUT_RDWR);
  close(sock);
}

void Session::run() {
  epoll_event triggeredEvent[2];
  epoll_event event;
  Epoll ep;

  event.events = EPOLLIN;
  event.data.fd = 0;
  checkError(epoll_ctl(ep.fd, EPOLL_CTL_ADD, 0, &event), "Failed to add stdin to epoll");
  event.data.fd = sock;
  checkError(epoll_ctl(ep.fd, EPOLL_CTL_ADD, sock, &event), "Failed to add sock to epoll");

  std::string secret;
  std::cout << "You can start to send the message...\n";
  while (running) {
    int cnt = epoll_wait(ep.fd, triggeredEvent, 2, 500);
    for (int i = 0; i < cnt; i++) {
      if (triggeredEvent[i].data.fd == 0) {
        std::getline(std::cin, secret);
      } else {
        ssize_t readCount = recvfrom(sock, recvBuffer, sizeof(recvBuffer), 0,
                                     reinterpret_cast<sockaddr*>(&addr), &addrLen);
        checkError(readCount, "Failed to read sock");
        state.sendAck = false;
        dissect(readCount);
        if (state.sendAck) encapsulate("");
        if (!secret.empty() && state.recvPacket) {
          encapsulate(secret);
          secret.clear();
        }
      }
    }
  }
}

void Session::dissect(ssize_t rdcnt) {
  auto payload = std::span{recvBuffer, recvBuffer + rdcnt};
  // TODO: NOTE
  // In following packet dissection code, we should set parameters if we are
  // receiving packets from remote
  dissectIPv4(payload);
}

void Session::dissectIPv4(std::span<uint8_t> buffer) {
  auto&& hdr = *reinterpret_cast<iphdr*>(buffer.data());
  int header_len = hdr.ihl * 4;
  if (ipToString(hdr.saddr) == config.remote.c_str()) {
    // Set `recvPacket = true` if we are receiving packet from remote
    state.recvPacket = true;
  } else {
    // Track current IP id
    state.recvPacket = false;
    state.ipId = hdr.id;
  }
  // Call dissectESP(payload) if next protocol is ESP
  auto payload = buffer.last(buffer.size() - header_len);
  if (hdr.protocol == IPPROTO_ESP) {
    dissectESP(payload);
  }
}

void Session::dissectESP(std::span<uint8_t> buffer) {
  auto&& hdr = *reinterpret_cast<ESPHeader*>(buffer.data());
  int hashLength = config.aalg->hashLength();
  // Strip hash
  buffer = buffer.subspan(sizeof(ESPHeader), buffer.size() - sizeof(ESPHeader) - hashLength);
  std::vector<uint8_t> data;
  // Decrypt payload
  if (!config.ealg->empty()) {
    data = config.ealg->decrypt(buffer);
    buffer = std::span{data.data(), data.size()};
  }

  // TODO:
  // Track ESP sequence number
  if (state.recvPacket == false) {
    state.espseq = ntohl(hdr.seq);
    config.spi = ntohl(hdr.spi);
  }
  // Call dissectTCP(payload) if next protocol is TCP
  struct ESPTrailer esp_trailer;
  esp_trailer.next = buffer.back();
  buffer = buffer.first(buffer.size() - 1);
  esp_trailer.padlen = buffer.back();
  auto next_payload = buffer.first(buffer.size() - esp_trailer.padlen - 1);
  if (esp_trailer.next == IPPROTO_TCP) {
    dissectTCP(next_payload);
  }
}

void Session::dissectTCP(std::span<uint8_t> buffer) {
  auto&& hdr = *reinterpret_cast<tcphdr*>(buffer.data());
  auto length = hdr.doff << 2;
  auto payload = buffer.last(buffer.size() - length);
  // Track tcp parameters
  state.tcpseq = ntohl(hdr.seq);
  state.tcpackseq = ntohl(hdr.ack_seq);
  state.srcPort = ntohs(hdr.source);
  state.dstPort = ntohs(hdr.dest);

  // Is ACK message?
  if (payload.empty()) return;
  state.tcpseq += payload.size();
  // We only got non ACK when we receive secret, then we need to send ACK
  if (state.recvPacket) {
    std::cout << "Secret: " << std::string(payload.begin(), payload.end()) << std::endl;
    state.sendAck = true;
    state.espseq += 1;
  }
}
void Session::encapsulate(const std::string& payload) {
  auto buffer = std::span{sendBuffer};
  std::fill(buffer.begin(), buffer.end(), 0);
  int totalLength = encapsulateIPv4(buffer, payload);
  sendto(sock, sendBuffer, totalLength, 0, reinterpret_cast<sockaddr*>(&addr), addrLen);
}

int Session::encapsulateIPv4(std::span<uint8_t> buffer, const std::string& payload) {
  auto&& hdr = *reinterpret_cast<iphdr*>(buffer.data());
  // TODO: Fill IP header
  hdr.version = 4;
  hdr.ihl = 5;
  hdr.ttl = 16;
  hdr.id = htons(ntohs(state.ipId) + 1);
  hdr.protocol = IPPROTO_ESP;
  hdr.frag_off = htons(0x4000);
  hdr.saddr = inet_addr(config.local.c_str());
  hdr.daddr = inet_addr(config.remote.c_str());
  auto nextBuffer = buffer.last(buffer.size() - sizeof(iphdr));

  int payloadLength = encapsulateESP(nextBuffer, payload);
  payloadLength += sizeof(iphdr);

  hdr.tot_len = htons(payloadLength);
  hdr.check = calculateIPChecksum(hdr);
  return payloadLength;
}

int Session::encapsulateESP(std::span<uint8_t> buffer, const std::string& payload) {
  auto&& hdr = *reinterpret_cast<ESPHeader*>(buffer.data());
  auto nextBuffer = buffer.last(buffer.size() - sizeof(ESPHeader));
  // TODO: Fill ESP header
  hdr.spi = htonl(config.spi);
  hdr.seq = htonl(state.espseq + 1);
  int payloadLength = encapsulateTCP(nextBuffer, payload);

  auto endBuffer = nextBuffer.last(nextBuffer.size() - payloadLength);
  // TODO: Calculate padding size and do padding in `endBuffer`
  uint8_t padSize = (4 - ((payloadLength + sizeof(ESPTrailer)) % 4)) % 4;
  std::iota(endBuffer.begin(), endBuffer.begin() + padSize, 1);
  payloadLength += padSize;
  // ESP trailer
  endBuffer[padSize] = padSize;
  endBuffer[padSize + 1] = IPPROTO_TCP;
  payloadLength += sizeof(ESPTrailer);
  // Do encryption
  if (!config.ealg->empty()) {
    auto result = config.ealg->encrypt(nextBuffer.first(payloadLength));
    std::copy(result.begin(), result.end(), nextBuffer.begin());
    payloadLength = result.size();
  }
  payloadLength += sizeof(ESPHeader);

  if (!config.aalg->empty()) {
    // TODO: Fill in config.aalg->hash()'s parameter
    auto result = config.aalg->hash(std::span{buffer.data(), (size_t)payloadLength});
    std::copy(result.begin(), result.end(), buffer.begin() + payloadLength);
    payloadLength += result.size();
  }
  return payloadLength;
}

int Session::encapsulateTCP(std::span<uint8_t> buffer, const std::string& payload) {
  auto&& hdr = *reinterpret_cast<tcphdr*>(buffer.data());
  if (!payload.empty()) hdr.psh = 1;
  // TODO: Fill TCP header
  hdr.ack = 1;
  hdr.doff = 5;
  hdr.dest = htons(state.srcPort);
  hdr.source = htons(state.dstPort);
  hdr.ack_seq = htonl(state.tcpseq);
  hdr.seq = htonl(state.tcpackseq);
  hdr.window = htons(502);
  auto nextBuffer = buffer.last(buffer.size() - sizeof(tcphdr));
  int payloadLength = 0;
  if (!payload.empty()) {
    std::copy(payload.begin(), payload.end(), nextBuffer.begin());
    payloadLength += payload.size();
  }
  // TODO: Update TCP sequence number
  state.tcpackseq += payload.size();
  payloadLength += sizeof(tcphdr);
  // TODO: Compute checksum
  struct PseudoIPv4Header ip_hdr;
  ip_hdr.src = inet_addr(config.local.c_str());
  ip_hdr.dst = inet_addr(config.remote.c_str());
  ip_hdr.protocol = IPPROTO_TCP;
  hdr.check = calculateTCPChecksum(ip_hdr, hdr, payload);
  return payloadLength;
}