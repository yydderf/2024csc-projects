
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
    - [ ] Scan for available WiFi devices / VMs
    - [ ] ARP Spoofing
        - [ ] Generate ARP reply (ref: https://github.com/Abhijay90/arp_packet_generate/tree/master)
        - [ ] Send Spoofed ARP replies to the victim
    - [ ] Get Username / Password from webpage
        - [ ] Get request from victim (listen on port 80)
        - [ ] Send the request to the server
- [ ] Pharm Attack
    - [ ] Scan for available WiFi devices / VMs
    - [ ] DNS Spoofing (DNS format, Netfilter queue)
        - [ ] Intercept DNS request from the victim (listen on port 80)
        - [ ] Generate DNS reply 
        - [ ] Reply the victim with the wrong IP address
    - [ ] Redirect the home page of NYCU to phishing page
- [ ] Scan
    - [ ] Get IP Address
    - [ ] Get MAC Address