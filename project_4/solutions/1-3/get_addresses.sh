if [ "$#" -eq 0 ]; then
    LIBC="/lib/x86_64-linux-gnu/libc.so.6"
else
    LIBC="$1"
fi

# ropper - ROP gadget
ropper --file "$LIBC" --search "pop rdi; ret;"

# strings
strings -a -t x "$LIBC" | grep "/bin/sh"

# functions
readelf -s "$LIBC" | grep "system@@GLIBC"
readelf -s "$LIBC" | grep "exit@@GLIBC"