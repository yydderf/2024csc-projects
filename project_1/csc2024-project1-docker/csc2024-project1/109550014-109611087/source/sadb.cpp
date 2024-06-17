#include "sadb.h"

#include <arpa/inet.h>
#include <unistd.h>

#include <iomanip>
#include <iostream>

std::vector<uint8_t> auth_key;
std::vector<uint8_t> encrypt_key;

uint32_t *src = (uint32_t *)malloc(4096 * sizeof(uint32_t));
uint32_t *dst = (uint32_t *)malloc(4096 * sizeof(uint32_t));
uint32_t spi;

uint8_t auth;
uint8_t encrypt;

void handler_error(const char *err_msg)
{
  perror(err_msg);
  exit(1);
}

void get_sa(struct sadb_ext *ext) {
    struct sadb_sa *sa = (struct sadb_sa *)ext;
    if (sa->sadb_sa_exttype != SADB_EXT_SA) {
        return;
    }
    spi = ntohs(sa->sadb_sa_spi);
    auth = sa->sadb_sa_auth;
    encrypt = sa->sadb_sa_encrypt;
}

void get_address(struct sadb_ext *ext) {
    struct sadb_address *addr = (struct sadb_address *)ext;
    auto exttype = addr->sadb_address_exttype;
    if (exttype == SADB_EXT_ADDRESS_SRC) {
      memcpy(src, (char *)addr + sizeof(struct sadb_address)+4, (addr->sadb_address_len*8-sizeof(struct sadb_address))*8);
    }
    else if (exttype == SADB_EXT_ADDRESS_DST) {
      memcpy(dst, (char *)addr + sizeof(struct sadb_address)+4, (addr->sadb_address_len*8-sizeof(struct sadb_address))*8);
    }
}

void get_key(struct sadb_ext *ext) {

  //change to different data type
  struct sadb_key *key = (struct sadb_key *)ext;
	auto keytype = key->sadb_key_exttype;

  //check if the key is auth or encrypt
  if (keytype == SADB_EXT_KEY_AUTH) {
      auth_key = std::vector<uint8_t>((char *)ext + sizeof(struct sadb_key), (char *)ext + ext->sadb_ext_len * 8);
  } else if (keytype == SADB_EXT_KEY_ENCRYPT) {
      encrypt_key = std::vector<uint8_t>((char *)ext + sizeof(struct sadb_key), (char *)ext + ext->sadb_ext_len * 8);
  }
}

void proc_sadb_msg(struct sadb_msg *msg, int msglen) {

  struct sadb_ext *ext;

  // Check if the message version is correct
  if(msg->sadb_msg_version != PF_KEY_V2) {
    fprintf(stderr,"Invalid PF_KEY version\n");
    return;
  }

  // Check if the message length is correct
  if(msglen != msg->sadb_msg_len*8) {
    fprintf(stderr,"Invalid message length\n");
    return;
  }
  
  // general error message
  if(msg->sadb_msg_errno!=0) {
    fprintf(stderr,"Error: %s\n",strerror(msg->sadb_msg_errno));
    return;
  }

  //no extensions
  if(msglen == sizeof(struct sadb_msg)) {
    fprintf(stderr,"No SADB entries found\n");
    return;
  }

  //parse the extensions
  msglen -= sizeof(struct sadb_msg);
  ext = (struct sadb_ext *)(msg+1);

  while(msglen > 0){
    if(ext->sadb_ext_type == SADB_EXT_SA) get_sa(ext);
    else if(ext->sadb_ext_type == SADB_EXT_ADDRESS_SRC) get_address(ext);
    else if(ext->sadb_ext_type == SADB_EXT_ADDRESS_DST) get_address(ext);
    else if(ext->sadb_ext_type == SADB_EXT_ADDRESS_PROXY) get_address(ext);
    else if(ext->sadb_ext_type == SADB_EXT_KEY_AUTH) get_key(ext);
    else if(ext->sadb_ext_type == SADB_EXT_KEY_ENCRYPT) get_key(ext);
    //move to the next extension
    msglen -= ext->sadb_ext_len*8;
    ext = (struct sadb_ext *)((caddr_t)ext + ext->sadb_ext_len*8);
  }
}

std::optional<ESPConfig> getConfigFromSADB() {
  // Allocate buffer
  char buf[4096];
  sadb_msg msg{};
  int read_bytes;
  // TODO: Fill sadb_msg
  msg.sadb_msg_version = PF_KEY_V2;
  msg.sadb_msg_type = SADB_DUMP;
  msg.sadb_msg_satype = SADB_SATYPE_UNSPEC;
  msg.sadb_msg_len = sizeof(msg) / 8;
  msg.sadb_msg_pid = getpid();
  
  // TODO: Create a PF_KEY_V2 socket and write msg to it
  // Then read from socket to get SADB information
  int sock = socket(PF_KEY, SOCK_RAW, PF_KEY_V2);
  if (sock == -1) {
    handler_error("Socket creation error");
  }
  proc_sadb_msg(&msg, sizeof(msg));
  read_bytes= write(sock, &msg, sizeof(msg));
  if (read_bytes == -1) {
    handler_error("send error: ");
  }
  int size = 0;

  struct sadb_msg *msg_ptr;
  auto seq = msg_ptr->sadb_msg_seq;
  while (1) {
    int msglen;
    // /* Read and print SADB_DUMP replies until done 
    msglen = read(sock, &buf, sizeof(buf));
    msg_ptr = (struct sadb_msg *)&buf;
    proc_sadb_msg(msg_ptr, msglen);
    size += sizeof(*msg_ptr);
    if (msg_ptr->sadb_msg_seq == 0) {
      break;
    }
  }
  std::span<uint8_t> authKey = auth_key;
  std::span<uint8_t> encryptKey = encrypt_key;

	if (size != sizeof(sadb_msg)) {
    ESPConfig config{};
    // TODO: Parse SADB message
    config.spi = ntohl(spi);
    config.aalg = std::make_unique<ESP_AALG>(auth, authKey);
    // Have enc algorithm:
    // config.ealg = std::make_unique<ESP_AALG>(SADB_AALG_SHA1HMAC, _key); ???
    // No enc algorithm:
    config.ealg = std::make_unique<ESP_EALG>(encrypt, encryptKey);
    // Source address:
    config.local = ipToString(*src);
    // Destination address:
    config.remote = ipToString(*dst);
    return config;
  }
  std::cerr << "SADB entry not found." << std::endl;
  return std::nullopt;
}

std::ostream &operator<<(std::ostream &os, const ESPConfig &config) {
  os << "------------------------------------------------------------" << std::endl;
  os << "AALG  : ";
  if (!config.aalg->empty()) {
    os << std::left << std::setw(30) << std::setfill(' ') << config.aalg->name();
    os << "HWACCEL: " << config.aalg->provider() << std::endl;
  } else {
    os << "NONE" << std::endl;
  }
  os << "EALG  : ";
  if (!config.ealg->empty()) {
    os << std::left << std::setw(30) << std::setfill(' ') << config.ealg->name();
    os << "HWACCEL: " << config.aalg->provider() << std::endl;
  } else {
    os << "NONE" << std::endl;
  }
  os << "Local : " << config.local << std::endl;
  os << "Remote: " << config.remote << std::endl;
  os << "------------------------------------------------------------";
  return os;
}