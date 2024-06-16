all: get_secret make_executables

get_secret:
	gcc time.c -o get_secret

make_executables:
	chmod +x I-1.py I-2.py I-3.py I-4.sh II-1.py

.PHONY:
clean:
	rm -rf get_secret