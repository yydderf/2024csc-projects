export PWD = "$(shell pwd)"

setup:
	chmod +x make_payload
	chmod +x crack_attack
	chmod +x attacker_server
	@if [ "${PWD}" != "/app" ]; then mv worm /app/worm; fi
	rm -f combination.txt

.PHONY:
clean:
	rm -f new_ls

pack:
	zip 109550014-109611087.zip Makefile attacker_server \
		crack_attack make_payload dummy_payload worm
