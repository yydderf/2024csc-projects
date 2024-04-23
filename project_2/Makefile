all: mitm_attack pharm_attack

mitm_attack: mitm_attack.cpp scan.cpp
	g++ -g mitm_attack.cpp scan.cpp -o mitm_attack

pharm_attack: pharm_attack.cpp scan.cpp
	g++ -g pharm_attack.cpp scan.cpp -o pharm_attack

.PHONY:
clean:
	rm mitm_attack pharm_attack
