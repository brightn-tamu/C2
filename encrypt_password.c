#include <stdio.h>
#include <string.h>
#include <openssl/evp.h>

#define SHIFT 3  // Define the Caesar cipher shift amount

// Function to apply a Caesar cipher to the password
void caesar_cipher(char *password, int shift) {
    printf("Applying Caesar cipher with shift %d: Original password: %s\n", shift, password);
    for (int i = 0; i < strlen(password); i++) {
        // Apply shift only to alphabetic characters
        if (password[i] >= 'a' && password[i] <= 'z') {
            password[i] = ((password[i] - 'a' + shift) % 26) + 'a';
        } else if (password[i] >= 'A' && password[i] <= 'Z') {
            password[i] = ((password[i] - 'A' + shift) % 26) + 'A';
        }
    }
    printf("Password after Caesar cipher: %s\n", password);
}

// Function to encrypt the password
int encrypt_password(char *password, unsigned char *encrypted_password, unsigned char *key, unsigned char *iv) {
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    int len;
    int ciphertext_len;

    EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv);
    EVP_EncryptUpdate(ctx, encrypted_password, &len, (unsigned char *)password, strlen(password));
    ciphertext_len = len;

    EVP_EncryptFinal_ex(ctx, encrypted_password + len, &len);
    ciphertext_len += len;
    EVP_CIPHER_CTX_free(ctx);

    printf("Encrypting password (hex): ");
    for (int i = 0; i < ciphertext_len; i++) {
        printf("%02x", encrypted_password[i]);
    }
    printf("\n");
    printf("Password encrypted, length: %d\n", ciphertext_len);
    return ciphertext_len;
}

// Function for bitshift encryption
void bitshift_encrypt(unsigned char *data, int length) {
    printf("Applying bitshift encryption to data of length %d\n", length);
    for (int i = 0; i < length; i++) {
        data[i] = (data[i] << 1) | (data[i] >> 7);  // Left shift by 1 with wrap-around
    }
    printf("Data after bitshift encryption:\n");
    for (int i = 0; i < length; i++) {
        printf("%02x", data[i]);
    }
    printf("\n");
}

// Function for bitshift decryption
void bitshift_decrypt(unsigned char *data, int length) {
    printf("Applying bitshift decryption to data of length %d\n", length);
    for (int i = 0; i < length; i++) {
        data[i] = (data[i] >> 1) | (data[i] << 7);  // Right shift by 1 with wrap-around
    }
    printf("Data after bitshift decryption:\n");
    for (int i = 0; i < length; i++) {
        printf("%02x", data[i]);
    }
    printf("\n");
}

// Function to decrypt the password
int decrypt_password(unsigned char *encrypted_password, int encrypted_len, unsigned char *key, unsigned char *iv, char *decrypted_password) {
    printf("Decrypting password...\n");
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    int len;
    int plaintext_len;

    EVP_DecryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv);
    EVP_DecryptUpdate(ctx, (unsigned char *)decrypted_password, &len, encrypted_password, encrypted_len);
    plaintext_len = len;

    EVP_DecryptFinal_ex(ctx, (unsigned char *)decrypted_password + len, &len);
    plaintext_len += len;
    EVP_CIPHER_CTX_free(ctx);

    decrypted_password[plaintext_len] = '\0'; // Null-terminate the string
    printf("Decrypted password length: %d, Decrypted password: %s\n", plaintext_len, decrypted_password);

    return plaintext_len;
}

int main() {
    char correct_password[] = "swag_mesiah";
    unsigned char key[32] = "01234567890123456789012345678901";  // 256-bit key
    unsigned char iv[16] = "0123456789012345";                   // 128-bit IV

    unsigned char encrypted_password[128];
    char decrypted_password[128];

    // Encrypt the password
    printf("Original password: %s\n", correct_password);
    caesar_cipher(correct_password, SHIFT);
    int encrypted_len = encrypt_password(correct_password, encrypted_password, key, iv);
    bitshift_encrypt(encrypted_password, encrypted_len);

    // Print the encrypted password as hex
    printf("Encrypted password (hex): ");
    for (int i = 0; i < encrypted_len; i++) {
        printf("%02x", encrypted_password[i]);
    }
    printf("\n");

    // Decrypt the password
    bitshift_decrypt(encrypted_password, encrypted_len);
    decrypt_password(encrypted_password, encrypted_len, key, iv, decrypted_password);

    // Reverse the Caesar cipher to original
    caesar_cipher(decrypted_password, 26 - SHIFT); // Reverse shift

    // Print and compare
    printf("Decrypted password after Caesar reversal: %s\n", decrypted_password);
    if (strcmp(decrypted_password, "swag_mesiah") == 0) {
        printf("Decryption successful! Passwords match.\n");
    } else {
        printf("Decryption failed! Passwords do not match.\n");
    }

    return 0;
}
