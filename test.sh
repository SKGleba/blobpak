BLOBPAK_BIN="./blobpak"
BLOBPAK_INPUTS=inputs
BLOBPAK_OUTPUTS=outputs
BLOBPAK_RESULTS=results
DFL_PASSWORD='quite_strong_and_long_password'
TEST_PARAMS=("--math1v0" "--maxpad 4096" "--hashparam SHA256_AES_SHA1" "--enchdr" "--namesalt random_test_name_salt" "--pwdsalt very_salty_pwd_addon" "--aes128param AES_128_CCBC" "--maxpad 8192 --hashparam SHA256_AES_SHA1 --enchdr --namesalt random_test_name_salt --pwdsalt very_salty_pwd_addon --aes128param AES_128_CCBC")

# Test 1: Simple strings
TEST1_INPUT1='This is a test string'
TEST1_INPUT2='This is a multiline test string\nThis is the second line'
TEST1_INPUT3='This is a multiline string with special characters\n!@#$%^&*()_+\nThis is the third line'
function test1() {
    echo "Test 1: stdin input -> file output, file input -> stdout output"
    # Dump inputs
    echo -e "$TEST1_INPUT1" > "$BLOBPAK_INPUTS/test1.1.txt"
    echo -e "$TEST1_INPUT2" > "$BLOBPAK_INPUTS/test1.2.txt"
    echo -e "$TEST1_INPUT3" > "$BLOBPAK_INPUTS/test1.3.txt"
    # Encrypt
    echo "Encrypting..."
    test_num=1
    for test_param in "${TEST_PARAMS[@]}"; do
        for test_input in "$TEST1_INPUT1" "$TEST1_INPUT2" "$TEST1_INPUT3"; do
            echo "Encrypting [$test_num] [param: $test_param]..."
            echo -e "$test_input" | $BLOBPAK_BIN "$BLOBPAK_OUTPUTS/test1.blobpak" add test1.$test_num "$DFL_PASSWORD" --stdin $test_param > /dev/null
            test_num=$((test_num+1))
        done
    done
    test_count=$((test_num-1))
    # Decrypt & compare
    echo "Decrypting and comparing..."
    test_num=1
    for test_param in "${TEST_PARAMS[@]}"; do
        for test_input in "$TEST1_INPUT1" "$TEST1_INPUT2" "$TEST1_INPUT3"; do
            echo "Decrypting [$test_num] [param: $test_param]..."
            result=$($BLOBPAK_BIN "$BLOBPAK_OUTPUTS/test1.blobpak" get test1.$test_num "$DFL_PASSWORD" --stdout --threads 1 $test_param)
            diff <(echo -e "$test_input") <(echo -e "$result") > /dev/null
            if [ $? -eq 0 ]; then
                echo "Test 1.$test_num: PASSED"
            else
                echo "Test 1.$test_num: FAILED"
                echo -ne "$result" > "$BLOBPAK_RESULTS/test1.$test_num.txt"
                exit 1
            fi
            test_num=$((test_num+1))
        done
    done
}

# Test 2: Binary files
function test2() {
    echo "Test 2: stdin input -> file output"
    # Create input files (random binary data)
    echo "Creating input files..."
    ## below the block size
    dd if=/dev/random of="$BLOBPAK_INPUTS/test2.1.bin" bs=1 count=13 > /dev/null 2>&1
    ## multiple of block size 
    dd if=/dev/random of="$BLOBPAK_INPUTS/test2.2.bin" bs=16 count=212 > /dev/null 2>&1
    ## unaligned to block size
    dd if=/dev/random of="$BLOBPAK_INPUTS/test2.3.bin" bs=1 count=1223133 > /dev/null 2>&1
    ## file
    dd if=/dev/random of="$BLOBPAK_INPUTS/test2.4.bin" bs=16 count=1048576 > /dev/null 2>&1
    # Encrypt
    echo "Encrypting..."
    test_num=1
    for test_param in "${TEST_PARAMS[@]}"; do
        for test_input_n in {1..4}; do
            test_input="$BLOBPAK_INPUTS/test2.$test_input_n.bin"
            echo "Encrypting [$test_num] $test_input [param: $test_param]..."
            cat "$test_input" | $BLOBPAK_BIN "$BLOBPAK_OUTPUTS/test2.$test_input_n.blobpak" add test2.$test_num "$DFL_PASSWORD" --stdin $test_param > /dev/null
            test_num=$((test_num+1))
        done
    done
    test_count=$((test_num-1))
    # Decrypt & compare
    echo "Decrypting and comparing..."
    test_num=1
    for test_param in "${TEST_PARAMS[@]}"; do
        for test_input_n in {1..4}; do
            test_input="$BLOBPAK_INPUTS/test2.$test_input_n.bin"
            echo "Decrypting [$test_num] $test_input [param: $test_param]..."
            $BLOBPAK_BIN "$BLOBPAK_OUTPUTS/test2.$test_input_n.blobpak" get test2.$test_num "$DFL_PASSWORD" --stdout --threads 1 $test_param | cmp "$test_input" > /dev/null
            if [ $? -eq 0 ]; then
                echo "Test 2.$test_num: PASSED"
            else
                echo "Test 2.$test_num: FAILED"
                $BLOBPAK_BIN "$BLOBPAK_OUTPUTS/test2.$test_input_n.blobpak" get test2.$test_num "$DFL_PASSWORD" --stdout --threads 1 $test_param > "$BLOBPAK_RESULTS/test2.$test_num.bin"
                exit 1
            fi
            test_num=$((test_num+1))
        done
    done
}

rm -rf "$BLOBPAK_INPUTS"
rm -rf "$BLOBPAK_OUTPUTS"
rm -rf "$BLOBPAK_RESULTS"
mkdir -p "$BLOBPAK_INPUTS"
mkdir -p "$BLOBPAK_OUTPUTS"
mkdir -p "$BLOBPAK_RESULTS"
test1
test2

