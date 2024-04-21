all: mitm_attack pharm_attack

mitm_attack: mitm_attack.cpp
	g++ mitm_attack.cpp -o mitm_attack

pharm_attack: pharm_attack.cpp
	g++ pharm_attack.cpp -o pharm_attack

.PHONY:
clean:
	rm mitm_attack pharm_attack
