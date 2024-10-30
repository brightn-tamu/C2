#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <openssl/sha.h>


#define PASSWORD_LENGTH 6  // Adjust if the password length changes
#define HASH_LENGTH SHA256_DIGEST_LENGTH  // 32 bytes for SHA-256 hash
#define LARGE_ARRAY_LENGTH 20  // Length of the larger array
#define SEED 42  // Fixed seed for consistent pseudo-random positions


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



// Extract the key from the larger array using the same pseudo-random sequence
void extract_key_from_large_array(unsigned char *large_array, unsigned char *extracted_key, int key_length, int large_length, unsigned int seed) {
    srand(seed);

    // Extract key bytes from the same positions
    for (int j = 0; j < key_length; j++) {
        int position;
        do {
            position = rand() % large_length;
        } while (large_array[position] != large_array[j]);
        extracted_key[j] = large_array[position];
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

// Generate a larger array with the key embedded at pseudo-random positions
void generate_large_array(unsigned char *key, unsigned char *large_array, int key_length, int large_length, unsigned int seed) {
    srand(seed);

    // Fill the large array with random filler bytes
    for (int i = 0; i < large_length; i++) {
        large_array[i] = rand() % 256;
    }
    print_array("Large array with random filler bytes", large_array, large_length);

    // Embed key bytes at pseudo-random positions
    for (int j = 0; j < key_length; j++) {
        int position;
        do {
            position = rand() % large_length;
        } while (large_array[position] == key[j]);  // Ensure each key byte is uniquely positioned
        large_array[position] = key[j];
    }
    print_array("Large array with embedded encrypted key bytes", large_array, large_length);
}

int main() {
    const char *password = "Admin";  // Adjust the length and value of PASSWORD_LENGTH as needed
    unsigned char xor_key[PASSWORD_LENGTH] = {0x5A, 0x3B, 0x7D, 0x1E, 0xA5, 0x62};  // Encryption key
    unsigned char final_xor_key[PASSWORD_LENGTH] = {0x4F, 0x2A, 0x5E, 0x6C, 0xA8, 0x3D};  // Final XOR key
    unsigned char xor_result[PASSWORD_LENGTH];
    unsigned char evens[PASSWORD_LENGTH / 2];
    unsigned char odds[PASSWORD_LENGTH / 2];
    unsigned char sorted_combined[PASSWORD_LENGTH];
    unsigned char even_xor_key = 0x3C;
    unsigned char odd_xor_key = 0x5A;
    unsigned char hash[HASH_LENGTH];


    // Step 0: Generate SHA-256 hash of the password
    generate_sha256_hash(password, hash);
    print_array("Original SHA-256 hash", hash, HASH_LENGTH);

    // Step 1a: Print the original password in plaintext and in array format
    printf("Original password (plaintext): %s\n", password);
    print_array("Original password (array format)", (unsigned char *)password, PASSWORD_LENGTH);

    // Step 1b: XOR the password with the key
    xor_array((unsigned char *)password, xor_key, xor_result, PASSWORD_LENGTH);
    print_array("XORed result (Pre-encryption)", xor_result, PASSWORD_LENGTH);

    // Step 2: Split the XORed result into evens and odds
    split_array(xor_result, evens, odds, PASSWORD_LENGTH);
    print_array("Even-indexed elements", evens, PASSWORD_LENGTH / 2);
    print_array("Odd-indexed elements", odds, PASSWORD_LENGTH / 2);

    // Step 3: Shift the even-indexed elements
    shift_array(evens, PASSWORD_LENGTH / 2, 1);
    print_array("Shifted even-indexed elements", evens, PASSWORD_LENGTH / 2);

    // Step 4: XOR the even-indexed elements with a single key
    xor_with_key(evens, PASSWORD_LENGTH / 2, even_xor_key);
    print_array("Shifted and XORed even-indexed elements", evens, PASSWORD_LENGTH / 2);

    // Step 5: XOR the odd-indexed elements with a different key
    xor_with_key(odds, PASSWORD_LENGTH / 2, odd_xor_key);
    print_array("XORed odd-indexed elements", odds, PASSWORD_LENGTH / 2);

    // Step 6: Sort combined array as {even1, even2, ..., odd2, odd1}
    sort_combined(evens, odds, sorted_combined, PASSWORD_LENGTH);
    print_array("Combined Array (e1, e2, ..., o2, o1) format", sorted_combined, PASSWORD_LENGTH);

    // Step 7: Apply a final XOR to the entire combined array
    xor_array(sorted_combined, final_xor_key, sorted_combined, PASSWORD_LENGTH);
    print_array("Encrypted password with final XOR", sorted_combined, PASSWORD_LENGTH);

    // Step 8: Create a large array with embedded encrypted password
    unsigned char large_array[LARGE_ARRAY_LENGTH];
    generate_large_array(sorted_combined, large_array, PASSWORD_LENGTH, LARGE_ARRAY_LENGTH, SEED);
    print_array("Large array with embedded encrypted password", large_array, LARGE_ARRAY_LENGTH);


    // Decryption process
    printf("\n Deconstruction: \n");
    unsigned char reversed_evens[PASSWORD_LENGTH / 2];
    unsigned char reversed_odds[PASSWORD_LENGTH / 2];
    unsigned char reconstructed_xor_result[PASSWORD_LENGTH];

    // Step 8: Extract the encrypted password for decryption
    unsigned char extracted_key[PASSWORD_LENGTH];
    extract_key_from_large_array(large_array, extracted_key, PASSWORD_LENGTH, LARGE_ARRAY_LENGTH, SEED);
    print_array("Extracted key for decryption", extracted_key, PASSWORD_LENGTH);

    // Step 7 Reverse: Un-XOR with the final XOR key
    xor_array(sorted_combined, final_xor_key, sorted_combined, PASSWORD_LENGTH);

    // Step 6: Unsort combined array
    unsort_combined(sorted_combined, reversed_evens, reversed_odds, PASSWORD_LENGTH);
    print_array("Reversed even-indexed elements", reversed_evens, PASSWORD_LENGTH / 2);
    print_array("Reversed odd-indexed elements", reversed_odds, PASSWORD_LENGTH / 2);

    // Step 3 & 4: Un-XOR and unshift evens
    xor_with_key(reversed_evens, PASSWORD_LENGTH / 2, even_xor_key);
    unshift_array(reversed_evens, PASSWORD_LENGTH / 2, 1);
    print_array("Unshifted and un-XORed even-indexed elements", reversed_evens, PASSWORD_LENGTH / 2);

    // Step 5: Un-XOR odds
    xor_with_key(reversed_odds, PASSWORD_LENGTH / 2, odd_xor_key);
    print_array("Un-XORed odd-indexed elements", reversed_odds, PASSWORD_LENGTH / 2);

    // Step 2: Reconstruct the original XORed result
    for (int i = 0; i < PASSWORD_LENGTH; i++) {
        if (i % 2 == 0) {
            reconstructed_xor_result[i] = reversed_evens[i / 2];
        } else {
            reconstructed_xor_result[i] = reversed_odds[i / 2];
        }
    }
    print_array("Reconstructed XORed result", reconstructed_xor_result, PASSWORD_LENGTH);

    // Step 1: Final XOR with xor_key to retrieve original password
    unsigned char final_result[PASSWORD_LENGTH];
    xor_array(reconstructed_xor_result, xor_key, final_result, PASSWORD_LENGTH);
    print_array("Final reconstructed result after full reversal (Original password)", final_result, PASSWORD_LENGTH);

    if (arrays_match((unsigned char *)password, final_result, PASSWORD_LENGTH)) {
        printf("Success: Final reconstruction matches the original password.\n");
    } else {
        printf("Error: Final reconstruction does not match the original password.\n");
    }

    return 0;
}
