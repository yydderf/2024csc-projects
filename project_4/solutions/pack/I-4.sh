if [ "$#" -ne 1 ]; then
    echo "Usage: $0 [FILEPATH]"
    exit
fi

if [ -f "{$1}" ]; then
    echo "No such file or directory: $1"
    exit
fi

# stat "$1"
FLAG_INFO="$(binwalk -c "$1" | grep 'name' | awk -F' ' '{print $1" "$NF}')"
FLAG_INFO_ARR=($FLAG_INFO)

FLAG_OFFSET=${FLAG_INFO_ARR[0]}
FLAG_FILENAME=${FLAG_INFO_ARR[1]}
# echo $FLAG_OFFSET
# echo $FLAG_FILENAME

OUTPUT_FILENAME="out.zip"
dd if="$1" of="$OUTPUT_FILENAME" skip="$FLAG_OFFSET" bs=1 &>/dev/null
unzip -qq $OUTPUT_FILENAME

# echo $FLAG_FILENAME
# EXTRACTED_DIRECTORY="_$1.extracted"
# stat "$EXTRACTED_DIRECTORY"

tesseract flag.txt stdout
rm -rf $OUTPUT_FILENAME flag.txt