#!/usr/bin/bash
if [ "$#" -ne 1 ]; then
    echo "Usage $0 [host:port]"
    exit 1
fi

declare -a arr=("encoder" "sadb" "session" "util")

for i in "${arr[@]}"; do
    echo "Copying $i"
    curl "$1/source/$i.cpp" -o "source/$i.cpp"
done

rm -rf hijack
make