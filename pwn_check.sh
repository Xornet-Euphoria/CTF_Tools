#!/bin/bash

# requirement: rp++, checksec, rabin2(included radare2), one_gadget

usage() {
  echo "[+]: Usage -> ./pwn_check.sh <binary>"
  echo "              ./pwn_check.sh <binary> <libc> (search one_gadget)"
  exit 1
}

if [ $# -eq 0 ]; then
  usage
fi

binary="$1"
out="$1-check.txt"

# [todo]:
#if [ -e $out ]; then
#  echo "[+]: the file named $out is exists."
#  exit 1
#fi

# The result of checksec and rp++ are garbled with opening text editor.
# If you want to see perfect result, please use `cat <binary>-check.txt`.

echo "" > "$out"

/bin/checksec --file="$1" >> "$out"
echo -e "\n" >> "$out"
rabin2 -i "$binary" >> "$out"
echo -e "\n" >> "$out"
rabin2 -R "$binary" >> "$out"
echo -e "\n" >> "$out"
# [todo]: change argument of -r option
rp++ -f "$binary" --unique -r 8 >> "$out"
echo -e "\n" >> "$out"

if [ $# -gt 2]: then
  libc="$2"
  one_gadget "$libc" >> "$out"
fi

exit 0