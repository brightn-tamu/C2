#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <dirent.h>
#include <time.h>
#include <openssl/sha.h>

#if defined(_WIN32) || defined(_WIN64)
#include <windows.h>
#else
#include <unistd.h>  // Use for Unix-based systems
#endif

#define SEED 42
#define PASSWORD_LENGTH 6
#define LARGE_ARRAY_LENGTH 35
#define FLAG_COUNT 20
#define FILE_AMOUNT 51
#define INVALID_VALUE -1 // Use -1 as a placeholder for non-existing files

const char *hashed_key = "c1c224b03cd9bc7b6a86d77f5dace40191766c485cd55dc48caf9ac873335d6f";

unsigned char default_values[PASSWORD_LENGTH] = {0x43, 0x70, 0xb7, 0x54, 0xa6, 0x1d};

int File_exists[FILE_AMOUNT] = {0};
int Auth_status[FILE_AMOUNT] = {0};
long File_sizes[FILE_AMOUNT] = {0};
double Creation_minutes[FILE_AMOUNT] = {0};
double Modified_minutes[FILE_AMOUNT] = {0};
char Read_first_20[FILE_AMOUNT][21] = {0};
const char *file_names[FILE_AMOUNT] = {
    "config.yml",
    "user_data.json",
    "cache.bin",
    "secrets.env",
    "db_backup.sql",
    "session.log",
    "passwords.txt",
    "README.md",
    "network_settings.conf",
    "token.key",
    "data_export.csv",
    "notes.docx",
    "update.sh",
    "auth_history.log",
    "sdf1234.tmp",
    "xXf093@!.dat",
    "junkfile.xyz",
    "_____",
    "test123.bak",
    "random_numbers.txt",
    "xoxooxo.py",
    "out.bin",
    "GARBAGEFILE.NOPE",
    "NOPE.NOT",
    "a$$-data",
    "1234567890.cfg",
    "b4h6k3t8.tmp",
    "xpt9z_scramble.txt",
    "v__randomfile.cfg",
    "garbage_12.bin",
    "not_a_hint.dat",
    "uNkn0wnKey.txt",
    "dummy_data_01.bin",
    "flufffile.bak",
    "j5k9x.faux",
    "blahblahblah.doc",
    "config_backup.ini",
    "system_logs.txt",
    "cache_data.bin",
    "network_settings.conf",
    "session_data.tmp",
    "user_profiles.json",
    "error_report.log",
    "passwords_bak.txt",
    "firewall_rules.cfg",
    "auth_tokens.db",
    "sys_info_report.xml",
    "temp_credentials.txt",
    "debug_trace.log",
    "private_key.pem",
    "db_backup_2023.sql"
};


int xor_cycle = 0;
int cycle = 1;
int passTrue1 = 0;
int passTrue2 = 0;
int passTrue3 = 1;

//Array to hold encrypted key
unsigned char extracted_key[PASSWORD_LENGTH];
// Arrays to hold the separated even and odd elements
unsigned char reversed_evens[PASSWORD_LENGTH / 2];
unsigned char reversed_odds[PASSWORD_LENGTH / 2];
unsigned char password[50];

//Level-3 Array
int flags[FLAG_COUNT] = {0};

//Cycle key
int A[FLAG_COUNT] = {-1,1,-1,1,-1,1,-1,-1,1,1,1,1,1,1,-1,-1,1,1,1,1};

int function_a();
int function_b();
int function_c();
int function_d();
int function_last();
int array_function();
int file_check();
int end_function();

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
    /*Bunch of file operations
    
    //Set up checks for debugger and GDB 
    
    //False Initialization
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

    /*          prompt and check inputs- COMPLETE
                Some logic for level 2 array- COMPLETE
                Some logic checks for level 3

                encrypted payload: {0x43, 0x70, 0xb7, 0x54, 0xa6, 0x1d}
                "BANJO"
    */
    int function_a(){
        printf("In function_a\n");
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

        printf("passTrue1: %d, passTrue2: %d, passTrue3: %d\n", passTrue1, passTrue2, passTrue3);
        if(passTrue1 == 1 && passTrue2 == 1 && passTrue3 == 1) {
            end_function();
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

        passTrue1 = 1;
        //CORRECT PATH: caesar shift the password input
        //caesar_cipher(password,3);

        //Call next function (function_b)
        function_b();

    }

    /*          check for level 2 key (if level 1 has been completed) -COMPLETE
                Some logic for level 2 array- COMPLETE
                Some logic checks for level 3
    */



    int function_b(){
        printf("In function_b\n");
        // Define XOR keys
        unsigned char first_xor_key[PASSWORD_LENGTH] = {0x4F, 0x2A, 0x5E, 0x6C, 0xA8, 0x3D};
        unsigned char second_xor_key[PASSWORD_LENGTH] = {0x5A, 0x3B, 0x7D, 0x1E, 0xA5, 0x62};

        if (xor_cycle == 0 && extracted_key[0] == 0) {
            for (int i = 0; i < PASSWORD_LENGTH; i++) {
                extracted_key[i] = default_values[i];
            }

            if (extracted_key[0] != 0) {
                // First cycle: apply the first XOR key
                print_array("Extracted key for decryption", extracted_key, PASSWORD_LENGTH);
                for (int i = 0; i < PASSWORD_LENGTH; i++) {
                    extracted_key[i] = extracted_key[i] ^ first_xor_key[i % PASSWORD_LENGTH];
                }

                print_array("XOR key", extracted_key, PASSWORD_LENGTH);

                xor_cycle++;
            }
        }
        else if (xor_cycle == 0) {
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
        printf("In function_c\n");


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
    */
    int function_d() {
    printf("In function_d\n");

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
    //walks through the function cycle in some way (aka call function and develop through their loop)
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

    int end_function() {
        printf("In print loop\n");
        unsigned char final_result[PASSWORD_LENGTH + 1]; // Add space for null-terminator
        for (int i = 0; i < PASSWORD_LENGTH; i++) {
            final_result[i] = extracted_key[i];
        }
        final_result[PASSWORD_LENGTH] = '\0'; // Add null-terminator

        printf("Final result (hex): ");
        for (int i = 0; i < PASSWORD_LENGTH; i++) {
            printf("0x%02X ", final_result[i]);
        }
        printf("\n");

        // Print final_result as individual characters with ASCII verification
        printf("Final result (characters): ");
        for (int i = 0; i < PASSWORD_LENGTH; i++) {
            if (final_result[i] >= 0x20 && final_result[i] <= 0x7E) { // Check if printable ASCII
                printf("%c", final_result[i]);
            } else {
                printf("."); // Placeholder for non-printable characters
            }
        }
        printf("\n");

#if defined(_WIN32) || defined(_WIN64)
        Sleep(100);  // Sleep for 100 milliseconds on Windows
#else
        sleep(1);  // Sleep for 1 second on Unix-based systems
#endif
    }

// Function to check if a file exists
int file_exists(const char *filename) {
    struct stat buffer;
    return (stat(filename, &buffer) == 0); // Returns 0 if the file exists
}

int is_read_only(const char *filename) {
    struct stat file_stat;

    // Get the file's status
    if (stat(filename, &file_stat) != 0) {
        perror("stat error");
        return -1; // Error occurred
    }

    // Check if the file is read-only
    // For UNIX-like systems
    if ((file_stat.st_mode & S_IWUSR) == 0 && // No write permission for user
        (file_stat.st_mode & S_IWGRP) == 0 && // No write permission for group
        (file_stat.st_mode & S_IWOTH) == 0) { // No write permission for others
        return 1; // File is read-only
        }

    return 0; // File is not read-only
}

long get_file_size(const char *file_path) {
    struct stat file_stat;

    if (stat(file_path, &file_stat) != 0) {
        perror("stat error");
        return -1; // Error occurred
    }

    long file_size = file_stat.st_size;
    return file_size;
}

double minutes_since_creation(const char *file_path) {
    struct stat file_stat;

    // Get file statistics
    if (stat(file_path, &file_stat) != 0) {
        perror("stat error");
        return -1; // Indicates an error
    }

    // Get the creation time (change time on Unix-like systems)
    time_t creation_time = file_stat.st_ctime;
    time_t current_time = time(NULL); // Get current time

    // Calculate difference in seconds
    double seconds_since_creation = difftime(current_time, creation_time);
    double minutes_since_creation = seconds_since_creation / 60.0; // Convert seconds to minutes

    return minutes_since_creation; // Return the result
}

double minutes_since_last_modified(const char *file_path) {
    struct stat file_stat;

    // Get file statistics
    if (stat(file_path, &file_stat) != 0) {
        perror("stat error");
        return -1; // Indicates an error
    }

    // Get the last modified time
    time_t last_modified_time = file_stat.st_mtime;
    time_t current_time = time(NULL); // Get current time

    // Calculate difference in seconds
    double seconds_since_last_modified = difftime(current_time, last_modified_time);
    double minutes_since_last_modified = seconds_since_last_modified / 60.0; // Convert seconds to minutes

    return minutes_since_last_modified; // Return the result
}

// Function to read the first 20 characters from a file
void read_first_20_characters(const char *file_path, char *buffer, size_t buffer_size) {
    FILE *file = fopen(file_path, "r"); // Open the file in read mode
    if (file == NULL) {
        perror("Failed to open file");
        buffer[0] = '\0'; // Set buffer to empty string on error
        return;
    }

    // Read up to 20 characters from the file
    size_t chars_read = fread(buffer, sizeof(char), buffer_size - 1, file);
    buffer[chars_read] = '\0'; // Null-terminate the string

    fclose(file); // Close the file
}


int file_check() {
    // Iterate over files and populate the arrays
    for (int i = 0; i < FILE_AMOUNT; i++) {
        File_exists[i] = file_exists(file_names[i]);
        if (File_exists[i] == 0) { // If the file does not exist
            Auth_status[i] = INVALID_VALUE;
            File_sizes[i] = INVALID_VALUE;
            Creation_minutes[i] = INVALID_VALUE;
            Modified_minutes[i] = INVALID_VALUE;
            snprintf(Read_first_20[i], sizeof(Read_first_20[i]), "N/A"); // Indicate "N/A" for non-existing files
        } else { // If the file exists, gather actual data
            Auth_status[i] = is_read_only(file_names[i]);
            File_sizes[i] = get_file_size(file_names[i]);
            Creation_minutes[i] = minutes_since_creation(file_names[i]);
            Modified_minutes[i] = minutes_since_last_modified(file_names[i]);
            read_first_20_characters(file_names[i], Read_first_20[i], sizeof(Read_first_20[i]));
        }
    }
    //Maze will be built out here for logical order and simplicity and moved to the main functions

    //Cycle 1 Logic Comparisons
    //B1
    if(cycle == 1 && Auth_status[0] == 1 && File_sizes[1] > 2048) {
        flags[0] = -1; //1
        flags[2] = 1; //3
        flags[3] = 1; //4

    }
    //B2
    if(cycle == 1 && Creation_minutes[2] < 60 && Auth_status[3] == 0) {
        flags[0] = -1;  //1
        flags[3] = 1;  //4
        flags[4] = 1;  //5
    }
    //B3
    if(cycle == 1 && Modified_minutes[4] > 120 && File_sizes[5] == 1024) {
        flags[1] = 1; //2
        flags[6] = 1; //7
        flags[8] = 1; //9
    }
    //B4
    if(cycle == 1 && Auth_status[6] == -1 && File_sizes[7] < 500) {
        flags[2] = 1; //3
        flags[5] = 1; //6
        flags[6] = -1; //7
    }
    //B5
    if(cycle == 1 && strcmp(Read_first_20[8], "SECRET") == 0 && Creation_minutes[9] > 30) {
        flags[1] = 1; //2
        flags[8] = -1; //9
        flags[9] = 1; //10
    }
    //B6
    if(cycle == 1 && Auth_status[10] == 1 && Modified_minutes[11] < 15) {
        flags[0] = 1; //1
        flags[3] = 1; //4
        flags[5] = -1; //6
    }
    //B7
    if(cycle == 1 && File_sizes[12] > 4096 && Creation_minutes[13] == 45) {
        flags[1] = -1; //2
        flags[4] = 1; //5
        flags[9] = 1; //10
    }
    //B8
    if(cycle == 1 && Auth_status[14] == 0 && strcmp(Read_first_20[15], "PASSWORD") == 0) {
        flags[0] = -1; //1
        flags[2] = 1; //3
        flags[3] = 1; //4
    }
    //B9
    if (cycle == 1 && File_sizes[16] < 2048 && Auth_status[17] == 1) {
        flags[6] = 1; //7
        flags[7] = 1; //8
        flags[9] = -1; //10
    }
    //B10
    if(cycle == 1 && Modified_minutes[18] == 30 && Creation_minutes[19] > 60) {
        flags[2] = 1; //3
        flags[3] = 1; //4
        flags[8] = -1; //9
    }
    //B11
    if(cycle == 1 && strcmp(Read_first_20[20], "CONFIG") == 0 && File_sizes[21] > 1024) {
        flags[2] = -1; //3
        flags[3] = 1; //4
        flags[8] = 1; //9
    }
    //B12
    if(cycle == 1 && Auth_status[22] == 1 && Creation_minutes[23] < 10) {
        flags[0] = 1; //1
        flags[5] = 1; //6
        flags[7] = -1; //8
    }
    //B13
    if(cycle == 1 && File_sizes[24] == 512 && Auth_status[25] == 0) {
        flags[7] = 1; //8
        flags[8] = -1; //9
        flags[9] = 1; //10
    }
    //B14
    if(cycle == 1 && Modified_minutes[26] > 180 && strcmp(Read_first_20[27], "DATA") == 0) {
        flags[2] = 1; //3
        flags[5] = -1; //6
        flags[6] = 1; //7
    }
        //B15
        if(cycle == 1 && Creation_minutes[28] < 120 && Auth_status[29] == 1) {
            flags[5] = -1; //6
            flags[8] = 1; //9
            flags[9] = 1; //10
        }

        //B16
        if(cycle == 1 && File_sizes[30] > 3072 && Modified_minutes[31] < 5) {
            flags[2] = -1; //3
            flags[3] = 1; //4
            flags[9] = 1; //10
        }
        //B17
        if(cycle == 1 && strcmp(Read_first_20[32], "KEY") == 0 && Auth_status[33] == -1) {
            flags[1] = 1; //2
            flags[3] = 1; //4
            flags[6] = -1; //7
        }
        //B18
        if(cycle == 1 && File_sizes[34] < 768 && Creation_minutes[35] > 15) {
            flags[0] = 1; //1
            flags[2] = 1; //3
            flags[8] = -1; //9
        }
        //B19
        if(cycle == 1 && Auth_status[36] == 1 && Modified_minutes[37] == 60) {
            flags[0] = 1; //1
            flags[5] = 1; //6
            flags[8] = -1; //9
        }
        //B20
        if(cycle == 1 && Creation_minutes[38] < 45 && strcmp(Read_first_20[39], "LOG") == 0) {
            flags[2] = -1; //3
            flags[4] = 1; //5
            flags[6] = 1; //7
        }
        //B21
        if(cycle == 1 && File_sizes[40] > 2048 && Auth_status[41] == 0) {
            flags[1] = 1; //2
            flags[3] = 1; //4
            flags[9] = -1; //10
        }
        //B22
        if(cycle == 1 && Modified_minutes[42] < 30 && Creation_minutes[43] == 90) {
            flags[2] = 1; //3
            flags[4] = 1; //5
            flags[6] = -1; //7
        }
        //B23
        if(cycle == 1 && strcmp(Read_first_20[44], "INFO") == 0 && Auth_status[45] == 1) {
            flags[0] = -1; //1
            flags[2] = 1; //3
            flags[3] = 1; //4
        }
        //B24
        if(cycle == 1 && File_sizes[46] < 1500 && Modified_minutes[47] > 120) {
            flags[1] = 1; //2
            flags[4] = -1; //5
            flags[8] = 1; //9
        }
        //B25
        if(cycle == 1 && Auth_status[48] == 1 && Creation_minutes[49] < 60) {
            flags[0] = 1; //1
            flags[3] = 1; //4
            flags[6] = -1; //7
        }
        //B26
        if(cycle == 1 && File_sizes[50] > 256 && strcmp(Read_first_20[0], "START") == 0) {
            flags[1] = 1; //2
            flags[3] = 1; //4
            flags[5] = -1; //6
        }
        //B27
        if(cycle == 1 && Modified_minutes[1] == 15 && Auth_status[2] == 0) {
            flags[0] = -1; //1
            flags[2] = 1; //3
            flags[5] = 1; //6
        }
        //B28
        if(cycle == 1 && Creation_minutes[3] < 120 && File_sizes[4] == 1024) {
            flags[3] = 1; //4
            flags[5] = -1; //6
            flags[7] = 1; //8
        }
        //B29
        if(cycle == 1 && Auth_status[5] == 1 && strcmp(Read_first_20[6], "TOKEN") == 0) {
            flags[4] = -1; //5
            flags[5] = 1; //6
            flags[8] = 1; //9
        }
        //B30
        if(cycle == 1 && File_sizes[7] < 512 && Creation_minutes[8] > 45) {
            flags[1] = 1; //2
            flags[2] = -1; //3
            flags[9] = 1; //10
        }

    //Cycle 2
    //B1
    if(cycle == 2 && Auth_status[9] == -1 && Modified_minutes[10] < 15) {
        flags[10] = 1; //11
        flags[12] = -1; //13
        flags[14] = 1; //15
    }
    //B2
    if(cycle == 2 && strcmp(Read_first_20[11], "DB_BACKUP") == 0 && Auth_status[12] == 0) {
        flags[11] = 1; //12
        flags[15] = -1; //16
        flags[18] = 1; //19
    }
    //B3
    if(cycle == 2 && File_sizes[13] > 1024 && Creation_minutes[14] < 30) {
        flags[13] = 1; //14
        flags[16] = 1; //17
        flags[19] = -1; //20
    }
    //B4
    if(cycle == 2 && Auth_status[15] == 1 && Modified_minutes[16] == 45) {
        flags[10] = -1; //11
        flags[12] = 1; //13
        flags[17] = 1; //18
    }
    //B5
    if(cycle == 2 && File_sizes[17] < 256 && Creation_minutes[18] > 15) {
        flags[13] = -1; //14
        flags[15] = 1; //16
        flags[19] = 1; //20
    }
    //B6
    if(cycle == 2 && strcmp(Read_first_20[19], "PRIVATE") == 0 && Auth_status[20] == 1) {
        flags[11] = 1; //12
        flags[14] = -1; //15
        flags[16] = 1; //17
    }
    //B7
    if(cycle == 2 && Modified_minutes[21] > 180 && Creation_minutes[22] < 120) {
        flags[12] = 1; //13
        flags[17] = -1; //18
        flags[18] = 1; //19
    }
    //B8
    if(cycle == 2 && File_sizes[23] > 512 && Auth_status[24] == 0) {
        flags[11] = -1; //12
        flags[14] = 1; //15
        flags[15] = 1; //16
    }
    //B9
    if(cycle == 2 && Creation_minutes[25] == 90 && strcmp(Read_first_20[26], "USER_DATA") == 0) {
        flags[10] = 1; //11
        flags[16] = -1; //17
        flags[19] = 1; //19
    }
    //B10
    if(cycle == 2 && Auth_status[27] == -1 && File_sizes[28] < 1000) {
        flags[11] = 1; //12
        flags[13] = 1; //13
        flags[18] = -1; //19
    }
    //B11
    if(cycle == 2 && Modified_minutes[29] < 30 && Creation_minutes[30] == 60) {
        flags[12] = 1; //12
        flags[14] = -1; //15
        flags[17] = 1; //18
    }
    //B12
    if(cycle == 2 && strcmp(Read_first_20[31], "UPDATE") == 0 && Auth_status[32] == 1) {
        flags[10] = 1; //11
        flags[15] = -1; //16
        flags[18] = 1; //19
    }
    //B13
    if(cycle == 2 && File_sizes[33] > 2048 && Creation_minutes[34] > 90) {
        flags[11] = 1; //12
        flags[16] = 1; //17
        flags[19] = -1; //20
    }
    //B14
    if(cycle == 2 && Auth_status[35] == 0 && Modified_minutes[36] < 60) {
        flags[13] = 1; //14
        flags[17] = -1; //18
        flags[18] = 1; //19
    }
    //B15
    if(cycle == 2 && File_sizes[37] == 4096 && strcmp(Read_first_20[38], "DEBUG") == 0) {
        flags[12] = -1; //13
        flags[14] = 1; //15
        flags[15] = 1; //16
    }
    //B16
    if(cycle == 2 && Creation_minutes[39] < 15 && Auth_status[40] == -1) {
        flags[10] = 1; //11
        flags[13] = 1; //14
        flags[16] = -1; //17
    }
    //B17
    if(cycle == 2 && File_sizes[41] > 1024 && Modified_minutes[42] == 180) {
        flags[11] = 1; //12
        flags[12] = -1; //13
        flags[19] = 1; //20
    }
    //B18
    if(cycle == 2 && Auth_status[43] == 1 && strcmp(Read_first_20[44], "SESSION") == 0) {
        flags[13] = -1; //14
        flags[15] = 1; //16
        flags[17] = 1; //18
    }
    //B19
    if(cycle == 2 && Creation_minutes[45] > 30 && File_sizes[46] < 512) {
        flags[10] = 1; //11
        flags[16] = 1; //17
        flags[18] = -1; //18
    }
    //B20
    if(cycle == 2 && Auth_status[47] == 0 && Modified_minutes[48] > 90) {
        flags[11] = -1; //12
        flags[14] = 1; //15
        flags[18] = 1; //19
    }
    //B21
    if(cycle == 2 && File_sizes[49] > 768 && strcmp(Read_first_20[50], "TEMP") == 0) {
        flags[12] = 1; //13
        flags[15] = -1; //16
        flags[17] = 1; //18
    }
    //B22
    if(cycle == 2 && Creation_minutes[0] < 120 && Auth_status[1] == 1) {
        flags[10] = 1; //11
        flags[13] = -1; //14
        flags[19] = 1; //20
    }
    //B23
    if(cycle == 2 && Modified_minutes[2] == 60 && File_sizes[3] > 2048) {
        flags[11] = 1; //12
        flags[12] = -1; //13
        flags[18] = 1; //19
    }
    //B24
    if(cycle == 2 && Auth_status[4] == 0 && strcmp(Read_first_20[5], "AUTH_HISTORY") == 0) {
        flags[13] = 1; //14
        flags[14] = 1; //15
        flags[16] = -1; //17
    }
    //B25
    if(cycle == 2 && File_sizes[6] < 300 && Creation_minutes[7] > 45) {
        flags[10] = -1; //11
        flags[11] = 1; //12
        flags[16] = -1; //17
    }
    //B26
    if(cycle == 2 && Auth_status[8] == -1 && Modified_minutes[9] < 30) {
        flags[12] = 1; //13
        flags[17] = 1; //17
        flags[18] = -1; //19
    }
    //B27
    if(cycle == 2 && File_sizes[10] > 1500 && Auth_status[11] == 1) {
        flags[14] = -1; //15
        flags[15] = 1; //16
        flags[16] = 1; //17
    }
    //B28
    if(cycle == 2 && Creation_minutes[12] < 10 && strcmp(Read_first_20[13], "ENCRYPTED") == 0) {
        flags[10] = 1; //11
        flags[13] = -1; //14
        flags[16] = 1; //17
    }
    //B29
    if(cycle == 2 && Modified_minutes[14] > 180 && Auth_status[15] == 0) {
        flags[11] = 1; //12
        flags[12] = -1; //13
        flags[19] = 1; //20
    }
    //B30
    if(cycle == 2 && File_sizes[16] == 2048 && Creation_minutes[17] > 60) {
        flags[14] = 1; //15
        flags[16] = 1; //17
        flags[18] = -1; //19
    }

    //Some extra seasoning (hide anywhere possible)
    if(Auth_status[0] == 1) {
        flags[2] = 0;
    }
    if(File_sizes[1] < 1024) {
        flags[5] = 0;
    }
    if(Auth_status[5] == 0) {
        flags[9] = 0;
    }
    if(Creation_minutes[7] >= 3) {
        flags[7] = 0;
    }
    if(Creation_minutes[2] < 5) {
        flags[10] = 0;
    }
    if(strcmp(Read_first_20[9], "CONFIG") != 0) {
        flags[19] = 0;
    }
    if(strcmp(Read_first_20[14], "KEY") == 0) {
        flags[3] = 0;
    }
    if(strcmp(Read_first_20[19], "LOG") == 0) {
        flags[17] = 0;
    }
    if(strcmp(Read_first_20[30], "GRAPE") == 0) {
        flags[2] = 0;
    }
    if(strcmp(Read_first_20[17], "TWIG") == 0) {
        flags[5] = 0;
    }
    if(strcmp(Read_first_20[7], "DREAMS") == 0) {
        flags[16] = 0;
    }
    if(strcmp(Read_first_20[35], "WALK") == 0) {
        flags[15] = 0;
    }

    //Comparison
    for (int i = 0; i < FLAG_COUNT; i++) {
        if (flags[i] == A[i]) {
            printf("Flag %c matches A[%d]: %d\n", 'a' + i, i, A[i]);
        } else {
            printf("Flag %c does not match A[%d]: %d\n", 'a' + i, i, A[i]);
        }
    }
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