#include <stdio.h>
#include <string.h>
#include <openssl/sha.h>

#define HASH_LENGTH SHA256_DIGEST_LENGTH  // 32 bytes for SHA-256 hash

void generate_sha256_hash(const char *input, unsigned char *output) {
    SHA256((unsigned char *)input, strlen(input), output);
}

void xor_array(const unsigned char *input, const unsigned char *key, unsigned char *output, int length) {
    for (int i = 0; i < length; i++) {
        output[i] = input[i] ^ key[i % length];
    }
}

void split_array(const unsigned char *input, unsigned char *evens, unsigned char *odds, int length) {
    int even_index = 0, odd_index = 0;
    for (int i = 0; i < length; i++) {
        if (i % 2 == 0) {
            evens[even_index++] = input[i];
        } else {
            odds[odd_index++] = input[i];
        }
    }
}

void shift_array(unsigned char *array, int length, int shift_amount) {
    for (int i = 0; i < length; i++) {
        array[i] = (array[i] << shift_amount) | (array[i] >> (8 - shift_amount));
    }
}

void xor_with_key(unsigned char *array, int length, unsigned char xor_key) {
    for (int i = 0; i < length; i++) {
        array[i] ^= xor_key;
    }
}

void sort_combined(const unsigned char *evens, const unsigned char *odds, unsigned char *combined, int length) {
    int half_length = length / 2;
    for (int i = 0; i < half_length; i++) {
        combined[i] = evens[i];
    }
    for (int i = 0; i < half_length; i++) {
        combined[half_length + i] = odds[half_length - 1 - i];
    }
}

void unsort_combined(const unsigned char *combined, unsigned char *evens, unsigned char *odds, int length) {
    int half_length = length / 2;
    for (int i = 0; i < half_length; i++) {
        evens[i] = combined[i];
    }
    for (int i = 0; i < half_length; i++) {
        odds[half_length - 1 - i] = combined[half_length + i];
    }
}

void unshift_array(unsigned char *array, int length, int shift_amount) {
    for (int i = 0; i < length; i++) {
        array[i] = (array[i] >> shift_amount) | (array[i] << (8 - shift_amount));
    }
}

int arrays_match(const unsigned char *a, const unsigned char *b, int length) {
    for (int i = 0; i < length; i++) {
        if (a[i] != b[i]) {
            return 0;
        }
    }
    return 1;
}

void print_array(const char *label, const unsigned char *array, int length) {
    printf("%s: ", label);
    for (int i = 0; i < length; i++) {
        printf("0x%02x", array[i]);
        if (i < length - 1) {
            printf(", ");
        }
    }
    printf("\n");
}

int main() {
    const char *password = "Admin";  // The password to hash
    unsigned char hash[HASH_LENGTH];
    unsigned char xor_key[HASH_LENGTH] = {
        0x5A, 0x9B, 0x3D, 0x7F, 0x1E, 0xC6, 0xA2, 0x47,
        0xD8, 0x39, 0xB4, 0xEF, 0x6C, 0x92, 0x4F, 0x11,
        0x7A, 0x88, 0x53, 0x29, 0xFD, 0x72, 0xCE, 0x45,
        0x1B, 0xE6, 0x37, 0x5D, 0xB8, 0x9A, 0xC4, 0x2F
    };
    unsigned char xor_result[HASH_LENGTH];
    unsigned char evens[HASH_LENGTH / 2];
    unsigned char odds[HASH_LENGTH / 2];
    unsigned char sorted_combined[HASH_LENGTH];
    unsigned char even_xor_key = 0x3C;
    unsigned char odd_xor_key = 0x5A;

    // Step 1: Generate SHA-256 hash of the password
    generate_sha256_hash(password, hash);
    print_array("Original SHA-256 hash", hash, HASH_LENGTH);

    // Step 2: XOR the hash with the key
    xor_array(password, xor_key, xor_result, HASH_LENGTH);
    print_array("XORed result", xor_result, HASH_LENGTH);

    // Step 3: Split the XORed result into evens and odds
    split_array(xor_result, evens, odds, HASH_LENGTH);
    print_array("Even-indexed elements", evens, HASH_LENGTH / 2);
    print_array("Odd-indexed elements", odds, HASH_LENGTH / 2);

    // Step 4: Shift the even-indexed elements
    shift_array(evens, HASH_LENGTH / 2, 1);
    print_array("Shifted even-indexed elements", evens, HASH_LENGTH / 2);

    // Step 5: XOR the even-indexed elements with a single key
    xor_with_key(evens, HASH_LENGTH / 2, even_xor_key);
    print_array("Shifted and XORed even-indexed elements", evens, HASH_LENGTH / 2);

    // Step 6: XOR the odd-indexed elements with a different key
    xor_with_key(odds, HASH_LENGTH / 2, odd_xor_key);
    print_array("XORed odd-indexed elements", odds, HASH_LENGTH / 2);

    // Step 7: Sort combined array as {even1, even2, ..., odd2, odd1}
    sort_combined(evens, odds, sorted_combined, HASH_LENGTH);
    print_array("Final sorted combined array", sorted_combined, HASH_LENGTH);

    // Step 8: XOR the hash with the key
    xor_array(hash, xor_key, xor_result, HASH_LENGTH);
    print_array("XORed result", xor_result, HASH_LENGTH);

    // Reverse the operations to verify correctness
    unsigned char reversed_evens[HASH_LENGTH / 2];
    unsigned char reversed_odds[HASH_LENGTH / 2];
    unsigned char reconstructed_xor_result[HASH_LENGTH];

    // Unsort combined array
    unsort_combined(sorted_combined, reversed_evens, reversed_odds, HASH_LENGTH);
    print_array("Reversed even-indexed elements", reversed_evens, HASH_LENGTH / 2);
    print_array("Reversed odd-indexed elements", reversed_odds, HASH_LENGTH / 2);

    // Un-XOR and unshift evens
    xor_with_key(reversed_evens, HASH_LENGTH / 2, even_xor_key);
    unshift_array(reversed_evens, HASH_LENGTH / 2, 1);
    print_array("Unshifted and un-XORed even-indexed elements", reversed_evens, HASH_LENGTH / 2);

    // Un-XOR odds
    xor_with_key(reversed_odds, HASH_LENGTH / 2, odd_xor_key);
    print_array("Un-XORed odd-indexed elements", reversed_odds, HASH_LENGTH / 2);

    // Reconstruct the original XORed result
    for (int i = 0; i < HASH_LENGTH; i++) {
        if (i % 2 == 0) {
            reconstructed_xor_result[i] = reversed_evens[i / 2];
        } else {
            reconstructed_xor_result[i] = reversed_odds[i / 2];
        }
    }
    print_array("Reconstructed XORed result", reconstructed_xor_result, HASH_LENGTH);

    // Step 8 Reverse: XOR reconstructed result with `xor_key` again
    unsigned char final_result[HASH_LENGTH];
    xor_array(reconstructed_xor_result, xor_key, final_result, HASH_LENGTH);
    print_array("Final reconstructed result after Step 8 reversal", final_result, HASH_LENGTH);

    // Test if the reconstruction matches the original XORed result
    if (arrays_match(xor_result, reconstructed_xor_result, HASH_LENGTH)) {
        printf("Success: Reconstruction matches the original XORed result.\n");
    } else {
        printf("Error: Reconstruction does not match the original XORed result.\n");
    }

    return 0;
}
