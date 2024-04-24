#ifndef COMMAND_H
#define COMMAND_H

#include <cstdlib>
#include <sstream>

int modify_iptables_rule(std::string ifname, int toggle);

#endif
