#include <cstdlib>
#include <sstream>
#include <iostream>

int modify_iptables_rule(std::string ifname, int toggle)
{
    std::string toggle_str = toggle ? "A" : "D";
    std::stringstream ss;
    // ss << "iptables -" << toggle_str << " INPUT -i " << ifname << " -j NFQUEUE";
    // ss << "iptables -" << toggle_str << " INPUT -p tcp -i " << ifname << " --dport 80 -j NFQUEUE";
    // ss << "iptables -" << toggle_str << " INPUT -p tcp -j NFQUEUE --dport 80 -i " << ifname << " --queue-num 0";
    ss << "iptables -" << toggle_str << " FORWARD -p tcp --dport 80 -j NFQUEUE -i " << ifname << " --queue-num 0";
    std::cout << ss.str() << std::endl;
    return system(ss.str().c_str());
}
