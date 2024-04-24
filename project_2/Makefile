all: mitm_attack pharm_attack

mitm_attack: mitm_attack.cpp scan.cpp arp.cpp spoof.cpp
	g++ -g mitm_attack.cpp scan.cpp arp.cpp spoof.cpp -lnetfilter_queue -o mitm_attack

pharm_attack: pharm_attack.cpp scan.cpp arp.cpp spoof.cpp
	g++ -g pharm_attack.cpp scan.cpp arp.cpp spoof.cpp -o pharm_attack

.PHONY:
clean:
	rm mitm_attack pharm_attack
