#include <stdio.h>
#include <string.h>
#include <openssl/evp.h>

#define SHIFT 3  // Define the Caesar cipher shift amount

// Function to apply a Caesar cipher to the password
void caesar_cipher(char *password, int shift) {
    for (int i = 0; i < strlen(password); i++) {
        // Apply shift only to alphabetic characters
        if (password[i] >= 'a' && password[i] <= 'z') {
            password[i] = ((password[i] - 'a' + shift) % 26) + 'a';
        } else if (password[i] >= 'A' && password[i] <= 'Z') {
            password[i] = ((password[i] - 'A' + shift) % 26) + 'A';
        }
    }
}

// Encrypt the password
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

    return ciphertext_len;
}

void bitshift_encrypt(unsigned char *data, int length) {
    for (int i = 0; i < length; i++) {
        data[i] = (data[i] << 1) | (data[i] >> 7);  // Left shift by 1 with wrap-around
    }
}



int main() {
    char correct_password[] = "swag_mesiah";
    unsigned char key[32] = "01234567890123456789012345678901";  // 256-bit key
    unsigned char iv[16] = "0123456789012345";                   // 128-bit IV

    unsigned char encrypted_password[128];

    caesar_cipher(correct_password, SHIFT);

    int encrypted_len = encrypt_password(correct_password, encrypted_password, key, iv);

    bitshift_encrypt(encrypted_password, encrypted_len);

    for (int i = 0; i < encrypted_len; i++) {
        printf("%02x", encrypted_password[i]);
    }
    printf("\n");

}
