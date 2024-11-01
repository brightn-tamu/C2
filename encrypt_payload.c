#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <openssl/sha.h>

#define PASSWORD_LENGTH 6  // Adjust if the password length changes
#define HASH_LENGTH SHA256_DIGEST_LENGTH  // 32 bytes for SHA-256 hash
#define LARGE_ARRAY_LENGTH 35  // Length of the larger array
#define SEED 42  // Fixed offset for embedding


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
    const char *password = "BANJO";
    unsigned char xor_key[PASSWORD_LENGTH] = {0x5A, 0x3B, 0x7D, 0x1E, 0xA5, 0x62};
    unsigned char final_xor_key[PASSWORD_LENGTH] = {0x4F, 0x2A, 0x5E, 0x6C, 0xA8, 0x3D};
    unsigned char xor_result[PASSWORD_LENGTH];
    unsigned char evens[PASSWORD_LENGTH / 2];
    unsigned char odds[PASSWORD_LENGTH / 2];
    unsigned char sorted_combined[PASSWORD_LENGTH];
    unsigned char even_xor_key = 0x3C;
    unsigned char odd_xor_key = 0x5A;

    printf("Original password (plaintext): %s\n", password);
    print_array("Original password (array format)", (unsigned char *)password, PASSWORD_LENGTH);

    xor_array((unsigned char *)password, xor_key, xor_result, PASSWORD_LENGTH);
    print_array("XORed result (Pre-encryption)", xor_result, PASSWORD_LENGTH);

    split_array(xor_result, evens, odds, PASSWORD_LENGTH);
    print_array("Even-indexed elements", evens, PASSWORD_LENGTH / 2);
    print_array("Odd-indexed elements", odds, PASSWORD_LENGTH / 2);

    shift_array(evens, PASSWORD_LENGTH / 2, 1);
    print_array("Shifted even-indexed elements", evens, PASSWORD_LENGTH / 2);

    xor_with_key(evens, PASSWORD_LENGTH / 2, even_xor_key);
    print_array("Shifted and XORed even-indexed elements", evens, PASSWORD_LENGTH / 2);

    xor_with_key(odds, PASSWORD_LENGTH / 2, odd_xor_key);
    print_array("XORed odd-indexed elements", odds, PASSWORD_LENGTH / 2);

    sort_combined(evens, odds, sorted_combined, PASSWORD_LENGTH);
    print_array("Combined Array (e1, e2, ..., o2, o1) format", sorted_combined, PASSWORD_LENGTH);

    xor_array(sorted_combined, final_xor_key, sorted_combined, PASSWORD_LENGTH);
    print_array("Encrypted password with final XOR", sorted_combined, PASSWORD_LENGTH);


    printf("\n Deconstruction: \n");
    unsigned char reversed_evens[PASSWORD_LENGTH / 2];
    unsigned char reversed_odds[PASSWORD_LENGTH / 2];
    unsigned char reconstructed_xor_result[PASSWORD_LENGTH];

    //array_function

    //function_b
    xor_array(sorted_combined, final_xor_key, sorted_combined, PASSWORD_LENGTH);

    //function_c
    unsort_combined(sorted_combined, reversed_evens, reversed_odds, PASSWORD_LENGTH);
    print_array("Reversed even-indexed elements", reversed_evens, PASSWORD_LENGTH / 2);
    print_array("Reversed odd-indexed elements", reversed_odds, PASSWORD_LENGTH / 2);

    //function_d
    xor_with_key(reversed_evens, PASSWORD_LENGTH / 2, even_xor_key);
    unshift_array(reversed_evens, PASSWORD_LENGTH / 2, 1);
    print_array("Unshifted and un-XORed even-indexed elements", reversed_evens, PASSWORD_LENGTH / 2);

    //function_d
    xor_with_key(reversed_odds, PASSWORD_LENGTH / 2, odd_xor_key);
    print_array("Un-XORed odd-indexed elements", reversed_odds, PASSWORD_LENGTH / 2);

    //function_a
    for (int i = 0; i < PASSWORD_LENGTH; i++) {
        if (i % 2 == 0) {
            reconstructed_xor_result[i] = reversed_evens[i / 2];
        } else {
            reconstructed_xor_result[i] = reversed_odds[i / 2];
        }
    }
    print_array("Reconstructed XORed result", reconstructed_xor_result, PASSWORD_LENGTH);

    //function_b
    // Step 1: Final XOR with xor_key to retrieve original password
    unsigned char final_result[PASSWORD_LENGTH];
    xor_array(reconstructed_xor_result, xor_key, final_result, PASSWORD_LENGTH);
    print_array("Final reconstructed result after full reversal (Original password)", final_result, PASSWORD_LENGTH);
    printf("Original password (plaintext): %s\n", final_result);

    // Check if the decryption matches the original password
    if (arrays_match((unsigned char *)password, final_result, PASSWORD_LENGTH)) {
        printf("Success: Final reconstruction matches the original password.\n");
    } else {
        printf("Error: Final reconstruction does not match the original password.\n");
    }

    return 0;
}
