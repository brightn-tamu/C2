#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <dirent.h>
#include <openssl/sha.h>

#if defined(_WIN32) || defined(_WIN64)
#include <windows.h>
#else
#include <unistd.h>  // Use for Unix-based systems
#endif

#define SEED 42
#define PASSWORD_LENGTH 6
#define LARGE_ARRAY_LENGTH 35
const char *hashed_key = "c1c224b03cd9bc7b6a86d77f5dace40191766c485cd55dc48caf9ac873335d6f";

int xor_cycle = 0;
int passTrue1 = 1;
int passTrue2 = 0;

//Array to hold encrypted key
unsigned char extracted_key[PASSWORD_LENGTH];
// Arrays to hold the separated even and odd elements
unsigned char reversed_evens[PASSWORD_LENGTH / 2];
unsigned char reversed_odds[PASSWORD_LENGTH / 2];
unsigned char password[50];


int function_a();
int function_b();
int function_c();
int function_d();
int array_function();

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

        Level 2 encryption logic
            XOR the Password with an initial key.
            Split the result into even and odd indexed elements.
            Shift and XOR (Even-Indexed Elements).
            XOR (Odd-Indexed Elements).
            Combine the transformed even and odd elements into the final format.
            Apply an Additional XOR to the combined array as a final encryption step.
            Seed key in larger psuedo-random array

            Plain Key:
            0x41, 0x64, 0x6d, 0x69, 0x6e, 0x00
            Encrypted pre-seeded key:
            0x45, 0x36, 0xf5, 0x54, 0x85, 0x38
            Seeded array embedded encrypted password:
            0x67, 0xc6, 0x69, 0x73, 0x51, 0xf5, 0x54, 0x45,
            0x36, 0xcd, 0xba, 0x85, 0x38, 0xfb, 0xe3, 0x46,
            0x7c, 0xc2, 0x54, 0xf8, 0x1b, 0xe8, 0xe7, 0x8d,
            0x76, 0x5a, 0x2e, 0x63, 0x33, 0x9f, 0xc9, 0x9a,
            0x66, 0x32, 0x0d

            Constants: Seed= 42
                       Array Length = 35
                       Password Length = 6
                       First XOR Key = {0x5A, 0x3B, 0x7D, 0x1E, 0xA5, 0x62};
                       Second XOR Key = {0x4F, 0x2A, 0x5E, 0x6C, 0xA8, 0x3D};
                       Even XOR Key = 0x3C
                       Odd XOR Key = 0x5A
                       Shift amount = 1


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

    function_a();
}


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

        if( xor_cycle == 1) {
            for (int i = 0; i < PASSWORD_LENGTH; i++) {
                if (i % 2 == 0) {
                    extracted_key[i] = reversed_evens[i / 2];
                } else {
                    extracted_key[i] = reversed_odds[i / 2];
                }
            }

            print_array("Reconstructed XORed result", extracted_key, PASSWORD_LENGTH);

        }

        // Prompt the user to enter the password
        #if defined(_WIN32) || defined(_WIN64)
            Sleep(100);  // Sleep for 100 milliseconds on Windows
        #else
            sleep(1);  // Sleep for 1 second on Unix-based systems
        #endif

        //Works like shit 👍
        printf("Enter password: ");
        fflush(stdout);
        fflush(stdin);
        scanf("%19s", password);  // Read input, limiting to 19 characters to avoid overflow
        while (getchar() != '\n')
            continue;


        //CORRECT PATH: caesar shift the password input
        //caesar_cipher(password,3);

        //Call next function (function_b)
        function_b();

    }

    /*          check for level 2 key (if level 1 has been completed)
                Some logic for level 2 array
                Some logic checks for level 3

                key = Admin
                      c1c224b03cd9bc7b6a86d77f5dace40191766c485cd55dc48caf9ac873335d6f
                      using SHA-256
    */



    int function_b(){

        // Define XOR keys
        unsigned char first_xor_key[PASSWORD_LENGTH] = {0x4F, 0x2A, 0x5E, 0x6C, 0xA8, 0x3D};
        unsigned char second_xor_key[PASSWORD_LENGTH] = {0x5A, 0x3B, 0x7D, 0x1E, 0xA5, 0x62};

        if (xor_cycle == 0) {
            if (extracted_key[0] != 0) {
                // First cycle: apply the first XOR key
                print_array("Extracted key for decryption", extracted_key, PASSWORD_LENGTH);
                for (int i = 0; i < PASSWORD_LENGTH; i++) {
                    extracted_key[i] = extracted_key[i] ^ first_xor_key[i % PASSWORD_LENGTH];
                }

                print_array("XOR key", extracted_key, PASSWORD_LENGTH);

                xor_cycle++;
            }
        } else if (xor_cycle == 1) {
            // Second cycle: apply the second XOR key
            for (int i = 0; i < PASSWORD_LENGTH; i++) {
                extracted_key[i] = extracted_key[i] ^ second_xor_key[i % PASSWORD_LENGTH];
            }

            // At this point, decryption should be complete
            // Optionally, you could verify the result or end the function sequence here
            printf("Decryption process completed.\n");

            // Print the decrypted key array
            printf("Key array = ");
            for (int i = 0; i < PASSWORD_LENGTH; i++) {
                printf("0x%02x ", extracted_key[i]);  // Print each byte in hex format
            }
            printf("\n");

            xor_cycle++;
        }

        printf("Starting password hashing\n");
        unsigned char user_hashed_key[SHA256_DIGEST_LENGTH]; // SHA-256 hash storage

        // Hash the password
        SHA256((unsigned char *)password, strlen(password), user_hashed_key);
        printf(" password hashed\n");


        // Convert to hexadecimal string
        char hashed_key_hex[SHA256_DIGEST_LENGTH * 2 + 1]; // +1 for null terminator
        for (int i = 0; i < SHA256_DIGEST_LENGTH; i++) {
            sprintf(hashed_key_hex + (i * 2), "%02x", user_hashed_key[i]);
        }
        hashed_key_hex[SHA256_DIGEST_LENGTH * 2] = '\0'; // Null-terminate the string

        // Print the hash
        printf("Password Input: %s\n", password);
        printf("SHA-256 Hash: %s\n", hashed_key_hex);
        printf("User SHA-256 Hash: %s\n", hashed_key);

        //Compare hashed key to actual key hash
        if (strcmp(hashed_key_hex, hashed_key) == 0 && passTrue1 == 1) {
            passTrue2 = 1;
            printf("Hash matches\n");
        }
        else {
            printf("Hash doesn't match\n");
        }

        //CORRECT PATH: encrypt the shifted password
        unsigned char encrypted_password[128];
        //int encrypted_len = encrypt_password(password, encrypted_password, "01234567890123456789012345678901", "0123456789012345");

        // Move to the next function (function_c)
        function_c();
    }


    /*          check for level 1 password
                Some logic checks for level 3
    */
    int function_c(){

        if (xor_cycle == 1) {
            // Split extracted_key
            int half_length = PASSWORD_LENGTH / 2;
            for (int i = 0; i < half_length; i++) {
                reversed_evens[i] = extracted_key[i];
            }
            for (int i = 0; i < half_length; i++) {
                reversed_odds[half_length - 1 - i] = extracted_key[half_length + i];
            }

            print_array("Reversed even-indexed elements", reversed_evens, PASSWORD_LENGTH / 2);
            print_array("Reversed odd-indexed elements", reversed_odds, PASSWORD_LENGTH / 2);

        }



        //bitshift_encrypt(encrypt_password,encrypted_len);
        // Simple password check
        //if (strcmp(encrypted_password, correct_password) == 0 && passTrue1 != 1) {
        //    passTrue1 = 1;
        //}

        //Move to next function (function_d)
        function_d();
    }
    /*
                Final check for level 3 /payload
                call function_a
    */
    int function_d(){
        unsigned char even_xor_key = 0x3C; // Define your key for even indexed elements
        unsigned char odd_xor_key = 0x5A;   // Define your key for odd indexed elements

        if(xor_cycle == 1) {
            //XOR evens
            for (int i = 0; i < (PASSWORD_LENGTH / 2); i++) {
                reversed_evens[i] ^= even_xor_key;
            }

            //Shift evens
            for (int i = 0; i < (PASSWORD_LENGTH /2); i++) {
                reversed_evens[i] = (reversed_evens[i] >> 1) | (reversed_evens[i] << (8 - 1));
            }

            print_array("Unshifted and un-XORed even-indexed elements", reversed_evens, PASSWORD_LENGTH / 2);


            //XOR odds
            for (int i = 0; i < (PASSWORD_LENGTH / 2); i++) {
                reversed_odds[i] ^= odd_xor_key;
            }

            print_array("Un-XORed odd-indexed elements", reversed_odds, PASSWORD_LENGTH / 2);

        }

        function_a();
    }



    //Does not run, is beginning of logic path to retrieve the key-
    //should walk through the function cycle in some way (aka call function and develop through their loop)
    int array_function(){
        //Array setup
        unsigned char large_array[LARGE_ARRAY_LENGTH] = {
            0x67, 0xc6, 0x69, 0x73, 0x51, 0xf5, 0x54,
            0x45, 0x36, 0xcd, 0xba, 0x85, 0x38, 0xfb,
            0xe3, 0x46, 0x7c, 0xc2, 0x54, 0xf8, 0x1b,
            0xe8, 0xe7, 0x8d, 0x76, 0x5a, 0x2e, 0x63,
            0x33, 0x9f, 0xc9, 0x9a, 0x66, 0x32, 0x0d
        };

        //Extract the key
        for (int j = 0; j < PASSWORD_LENGTH; j++) {
            int position = (j ^ SEED) % LARGE_ARRAY_LENGTH;
            extracted_key[j] = large_array[position];
        }

        function_b();

        return 0;
    }


#define CHECK_FILES_IN_DIR(dir_path, offsets,...)                        \
    do {                                                                \
        DIR *dir = opendir(dir_path);                                    \
        if (!dir) {                                                     \
            perror("Failed to open directory");                         \
            exit(EXIT_FAILURE);                                         \

#define CHECK_FILES_IN_DIR(dir_path, offsets,...)                        \
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