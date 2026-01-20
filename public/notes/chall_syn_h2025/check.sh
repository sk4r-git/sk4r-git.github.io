#!/bin/bash

##### Argument checks #####
# Check if binary path is provided
if [ $# -ne 1 ]; then
    echo "[+] Usage: $0 <binary_path>"
    exit 1
fi

binary=$1

# Check if file exists and is readable
if [ ! -f "$binary" ] || [ ! -r "$binary" ]; then
    echo "[!] Error: File '$binary' does not exist or is not readable."
    exit 1
fi


##### First check: byte-wise palindrome #####
reversed_file=$(mktemp)
size=$(wc -c < "$binary")

# Read the file byte by byte in reverse order (in a very efficient way)
for ((i = size - 1; i >= 0; i--)); do
    dd if="$binary" bs=1 skip=$i count=1 2>/dev/null
done > "$reversed_file"

if cmp -s "$binary" "$reversed_file"; then
    echo "[+] First check passed: binary is a byte-wise palindrome."
    rm "$reversed_file"
else
    echo "[!] First check failed: binary is not a byte-wise palindrome."
    rm "$reversed_file"
    exit 1
fi



##### Second check: quine property #####
output_file="./output"
max_run_time=120

# Run the binary in the scratch container and capture output & return code
$binary > "$output_file"
return_code=$?

if [ $return_code -ne 0 ]; then
    echo "[!] Second check failed: binary execution returned non-zero status: $return_code."
    exit 1
fi

if cmp -s "$binary" "$output_file"; then
    echo "[+] Second check passed: binary is a true quine, its output matches itself."
else
    echo "[!] Second check failed: Is that a quine? Binary output does not match itself."
    exit 1
fi

echo "[+] Both checks passed: your binary is a very nice quinindrome!"
echo "[+] Your score: $size"