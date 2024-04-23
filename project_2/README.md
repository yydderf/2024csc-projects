
#### Quick Start

```bash
make

# execute mitm attack
./mitm_attack

# execute pharming attack
./pharm_attack
```

#### TODO
- [ ] MITM Attack
    - [x] Task I - Device Address Information Collection
        - [x] Get network interface info
        - [x] Scan for available WiFi devices / VMs
        - [x] Print the devices
    - [ ] Task II - ARP Spoofing (https://github.com/ML-Cai/ARPSpoofing/blob/master/main.cpp)
        - [ ] Generate ARP reply (ref: https://github.com/Abhijay90/arp_packet_generate/tree/master)
        - [ ] Send Spoofed ARP replies to the victim
    - [ ] Task III - Fetch user credentials from HTTP sessions
        - [ ] Get request from victim (listen on port 80)
        - [ ] Send the request to the server
- [ ] Pharm Attack
    - [x] Task I - Device Address Information Collection
        - [x] Get network interface info
        - [x] Scan for available WiFi devices / VMs
        - [x] Print the devices
    - [ ] Task II - ARP Spoofing (https://github.com/ML-Cai/ARPSpoofing/blob/master/main.cpp)
        - [ ] Generate ARP reply (ref: https://github.com/Abhijay90/arp_packet_generate/tree/master)
        - [ ] Send Spoofed ARP replies to the victim
    - [ ] Task IV - DNS Spoofing (DNS format, Netfilter queue)
        - [ ] Intercept DNS request from the victim (listen on port 80)
        - [ ] Generate DNS reply 
        - [ ] Reply the victim with the wrong IP address
        - [ ] Redirect the home page of NYCU to phishing page
