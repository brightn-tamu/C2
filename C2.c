#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <dirent.h>
#include <stdlib.h>
#include <windows.h>
#include <openssl/sha.h> 
#include <sys/stat.h>
#include <dirent.h>
#include <stdlib.h>
#include <encrypt_password.c>

// Check if Windows machine
#if defined(_WIN32) || defined(_WIN64)
int debugger_check() {
    return IsDebuggerPresent();
}

int is_vm_environment() {
    FILE *fp;
    char buffer[128];
    int is_vm = 0;

    // Check BIOS Serial Number
    fp = popen("wmic bios get serialnumber", "r");
    if (fp) {
        fgets(buffer, sizeof(buffer), fp); // Skip the header
        if (fgets(buffer, sizeof(buffer), fp)) {
            if (strcmp(buffer, "0") == 0) {
                is_vm = 1; // Detected VMware or VirtualBox
            }
        }
        pclose(fp);
    }

    // Check Computer Manufacturer
    if (is_vm) {
        if (fp) {
                fgets(buffer, sizeof(buffer), fp); // Skip the header
            if (fgets(buffer, sizeof(buffer), fp)) {
                if (strstr(buffer, "VMware") || strstr(buffer, "VirtualBox")) {
                    is_vm = 1; // Detected VMware or VirtualBox
                }
            }
            pclose(fp);
        }
    }
}

// Assuming Unix machine
#else
#include <sys/ptrace.h>
#include <unistd.h>

int debugger_check() {
    if (ptrace(PTRACE_TRACEME, 0, 1, 0) == -1) {
        return 1;
    }
    return 0;
}

int is_vm_environment() {
    return 0;
}

#endif

#define FILE_CHECKS() ;

/*
files
    config.yml
    user_data.json
    cache.bin
    secrets.env
    db_backup.sql
 #endif

#include <openssl/sha.h> 

#define FILE_CHECKS() ;

/*
files
    config.yml
    user_data.json
    cache.bin
    secrets.env
    db_backup.sql
    session.log
    passwords.txt
    README.md
    network_settings.conf
    token.key
    data_export.csv
    notes.docx
    update.sh
    auth_history.log
    sdf1234.tmp
    xXf093@!.dat
    junkfile.xyz
    _____
    test123.bak
    random_numbers.txt
    xoxooxo.py
    out.bin
    GARBAGEFILE.NOPE
    NOPE.NOT
    a$$-data
    1234567890.cfg
    b4h6k3t8.tmp
    xpt9z_scramble.txt
    v__randomfile.cfg
    garbage_12.bin
    not_a_hint.dat
    uNkn0wnKey.txt
    dummy_data_01.bin
    flufffile.bak
    j5k9x.faux
    blahblahblah.doc
    config_backup.ini
    system_logs.txt
    cache_data.bin
    network_settings.conf
    session_data.tmp
    user_profiles.json
    error_report.log
    passwords_bak.txt
    firewall_rules.cfg
    auth_tokens.db
    sys_info_report.xml
    temp_credentials.txt
    debug_trace.log
    private_key.pem
    db_backup_2023.sql
*/

int main() {
    
    //Hash for Level 2
    const char *hashed_key = "c1c224b03cd9bc7b6a86d77f5dace40191766c485cd55dc48caf9ac873335d6f";

    //Level 1/2 Passed?
    int passTrue1 = 0;
    int passTrue2 = 0;

    /*Bunch of file operations
    
    //Set up checks for debugger and GDB 
    
    //False Initialization

    //Call function_a
        Function_a 
            prompt and check inputs
            Some logic for level 2 array
            Some logic checks for level 3
            
            call function_b
                Function_B
                    check for level 2 key (if level 1 has been completed)
                    Some logic for level 2 array
                    Some logic checks for level 3

                    call function_c
                        Function_C
                            check for level 1 password 
                            Some logic checks for level 3

                            call function_d 
                                Function_D
                                    Final check for level 3 /payload
                                    call function_a

            
    */
    int debugger_present = debugger_check();
    int vm_present = is_vm_environment();

    char passTrue = 0;
    char password[20];

    //level 1 password: swag_mesiah
    //  step 1:caesar shift by 3
    //  step 2: encrypt 
    //    encryption key: 01234567890123456789012345678901
    //    encryption iv: 0123456789012345
    //  step 3: bitshift left by 1 with wraparound

    const char correct_password[] = "0ff12bb203c614375be303ce2ed0dc58";

    int password_check(char *correct_password) {
    char password[20];
    printf("Enter password: ");
    scanf("%19s", password);
    if (strcmp(password, correct_password) == 0) {
        return 1;
    }
    else {
        return 0;
    }
}

/*          prompt and check inputs
            Some logic for level 2 array
            Some logic checks for level 3
*/
int function_a(){

    // Prompt the user to enter the password
    printf("Enter password: ");
    scanf("%19s", password);  // Read input, limiting to 19 characters to avoid overflow
    //CORRECT PATH: caesar shift the password input
    caesar_cipher(password,3);

}

/*          check for level 2 key (if level 1 has been completed)
            Some logic for level 2 array
            Some logic checks for level 3

            key = Admin
                  c1c224b03cd9bc7b6a86d77f5dace40191766c485cd55dc48caf9ac873335d6f 
                  using SHA-256

                  Hex array format: unsigned char hashed_key[SHA256_DIGEST_LENGTH] = 
                  {0xc1, 0xc2, 0x24, 0xb0, 0x3c, 0xd9, 0xbc, 0x7b, 0x6a, 0x86, 0xd7, 0x7f, 
                  0x5d, 0xac, 0xe4, 0x01, 0x91, 0x76, 0x6c, 0x48, 0x5c, 0xd5, 0x5d, 0xc4, 
                  0x8c, 0xaf, 0x9a, 0xc8, 0x73, 0x33, 0x5d, 0x6f};

                      // Print the hash in a C-style binary array format
                        printf("unsigned char hashed_key[SHA256_DIGEST_LENGTH] = {");
                        for (int i = 0; i < SHA256_DIGEST_LENGTH; i++) {
                            printf("0x%02x", hash[i]);
                            if (i < SHA256_DIGEST_LENGTH - 1) {
                                    printf(", ");
                            }
                        }
                        printf("};\n");

                  Binary: 
                    Binary representation of hash:
                    11000001 11000010 00100100 10110000 00111100 11011001 10111100 01111011 01101010 10000110 
                    11010111 01111111 01011101 10101100 11100100 00000001 10010001 01110110 01101100 01001000 
                    01011100 11010101 01011101 11000100 10001100 10101111 10011010 11001000 01110011 00110011 
                    01011101 01101111 

                    void print_hash_as_binary_bits(unsigned char *hash) {
                    // Print each byte of the hash as an 8-bit binary string
                        printf("Binary representation of hash:\n");
                        for (int i = 0; i < SHA256_DIGEST_LENGTH; i++) {
                            for (int j = 7; j >= 0; j--) {
                                printf("%d", (hash[i] >> j) & 1);  // Extract each bit
                            }
                            printf(" ");  // Separate bytes with a space for readability
                        }
                        printf("\n");
                    }
*/


int function_b(){
    //Hash key input
    SHA256((unsigned char *)password, strlen(password), hashed_password);

    // Convert computed hash to a hexadecimal string for comparison
    char hashed_password_hex[SHA256_DIGEST_LENGTH * 2 + 1];
    for (int i = 0; i < SHA256_DIGEST_LENGTH; i++) {
        sprintf(hashed_password_hex + (i * 2), "%02x", hashed_password[i]);
    }

    //Compare hashed key to actual key hash
    if (strcmp(hashed_password_hex, hashed_key) == 0 && passTrue1 == 1) {
        passTrue2 = 1;
    }

    //CORRECT PATH: encrypt the shifted password
    unsigned char encrypted_password[128];
    int encrypted_len = encrypt_password(password, encrypted_password, "01234567890123456789012345678901", "0123456789012345");

}


/*          check for level 1 password 
            Some logic checks for level 3
*/
int function_c(){

    bitshift_encrypt(encrypt_password,encrypted_len);
        // Simple password check
    if (strcmp(encrypted_password, correct_password) == 0 && passTrue1 != 1) {
        passTrue1 = 1;
    }

}
/*
            Final check for level 3 /payload
            call function_a
*/
int function_d(){

}


//Does not run, is beginning of logic path to retrieve the key- 
//should walk through the function cycle in some way (aka call function and develop through their loop)
int array_function() {

}


#define CHECK_FILES_IN_DIR(dir_path, offsets...)                        \
    do {                                                                \
        DIR *dir = opendir(dir_path);                                    \
        if (!dir) {                                                     \
            perror("Failed to open directory");                         \
            exit(EXIT_FAILURE);                                         \

#define CHECK_FILES_IN_DIR(dir_path, offsets...)                        \
    do {                                                                \
        DIR *dir = opendir(dir_path);                                    \
        if (!dir) {                                                     \
            perror("Failed to open directory");                         \
            exit(EXIT_FAILURE);                                         \
        }                                                               \
                                                                        \
        struct dirent *entry;                                            \
        struct stat buf;                                                \
        int offset_list[] = {offsets};                                  \
        int num_offsets = sizeof(offset_list) / sizeof(int);            \
                                                                        \
        for (int i = 0; i < num_offsets; ++i) {                         \
            int offset = offset_list[i];                                 \
            rewinddir(dir); /* Reset directory pointer */               \
                                                                        \
            /* Traverse to the specified offset */                      \
            for (int j = 0; j <= offset && (entry = readdir(dir)); ++j); \
                                                                        \
            if (entry) {                                                \
                char full_path[512];                                     \
                snprintf(full_path, sizeof(full_path), "%s/%s", dir_path, entry->d_name); \
                printf("Checking file: %s\n", full_path);               \
                                                                        \
                if (stat(full_path, &buf) == 0) {                       \
                    /* Hidden logic */                                  \
                    if (buf.st_size == 1024) {                          \
                        printf("Key Found! Size matches.\n");           \
                    }                                                   \
                                                                        \
                    /* Additional logic */                              \
                    if (buf.st_mtime % 2 == 0) {                        \
                        printf("Secondary Key Logic Triggered!\n");     \
                    }                                                   \
                }                                                       \
            }                                                           \
        }                                                               \
        closedir(dir);                                                  \
    } while (0)



#define true 1
#define false 0