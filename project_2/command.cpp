#include <cstdlib>
#include <sstream>

int modify_iptables_rule(std::string ifname, int toggle)
{
    std::string toggle_str = toggle ? "A" : "D";
    std::stringstream ss;
    ss << "iptables -" << toggle_str << " INPUT -i " << ifname << " -j NFQUEUE";
    return system(ss.str().c_str());
}
