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
const char *hashed_key = "c1c224b03cd9bc7b6a86d77f5dace40191766c485cd55dc48caf9ac873335d6f";

int xor_cycle = 0;
int cycle = 1;
int passTrue1 = 0;
int passTrue2 = 0;
int passTrue3 = 0;

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
int function_last();
int array_function();
int file_check();

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

    /*          check for level 2 key (if level 1 has been completed) -COMPLETE
                Some logic for level 2 array- COMPLETE
                Some logic checks for level 3
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

    if (passTrue1 == 1 && passTrue2 == 1 && passTrue3 == 1) {
        function_last();
    }
        function_a();
    }

    int function_last() {
    printf("Payload");
    exit(0);
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
    /* logic for checking file contents needs added.
     * Using temporary variables
     *
     * Will probably retrieve and store data in arrays.
     * Temporarily doing this to work out logic
     */

    //Check if file exists
    int name1 = file_exists("Temp");
    int name2 = file_exists("Temp2");
    int name3 = file_exists("Temp3");
    int name4 = file_exists("Temp4");
    int name5 = file_exists("Temp5");
    int name6 = file_exists("Temp6");
    int name7 = file_exists("Temp7");
    int name8 = file_exists("Temp8");
    int name9 = file_exists("Temp9");
    int name10 = file_exists("Temp10");
    int name11 = file_exists("Temp11");
    int name12 = file_exists("Temp12");
    int name13 = file_exists("Temp13");
    int name14 = file_exists("Temp14");
    int name15 = file_exists("Temp15");

    //Check if it is read-only
    int auth1 = is_read_only("Temp");
    int auth2 = is_read_only("Temp2");
    int auth3 = is_read_only("Temp3");
    int auth4 = is_read_only("Temp4");
    int auth5 = is_read_only("Temp5");
    int auth6 = is_read_only("Temp6");
    int auth7 = is_read_only("Temp7");
    int auth8 = is_read_only("Temp8");
    int auth9 = is_read_only("Temp9");
    int auth10 = is_read_only("Temp10");
    int auth11 = is_read_only("Temp11");
    int auth12 = is_read_only("Temp12");
    int auth13 = is_read_only("Temp13");
    int auth14 = is_read_only("Temp14");
    int auth15 = is_read_only("Temp15");

    //Get file size
    long file_size1 = get_file_size("Temp");
    long file_size2 = get_file_size("Temp2");
    long file_size3 = get_file_size("Temp3");
    long file_size4 = get_file_size("Temp4");
    long file_size5 = get_file_size("Temp5");
    long file_size6 = get_file_size("Temp6");
    long file_size7 = get_file_size("Temp7");
    long file_size8 = get_file_size("Temp8");
    long file_size9 = get_file_size("Temp9");
    long file_size10 = get_file_size("Temp10");
    long file_size11 = get_file_size("Temp11");
    long file_size12 = get_file_size("Temp12");
    long file_size13 = get_file_size("Temp13");
    long file_size14 = get_file_size("Temp14");
    long file_size15 = get_file_size("Temp15");

    //Get minutes since creation
    double c_minutes1 = minutes_since_creation("Temp");
    double c_minutes2 = minutes_since_creation("Temp2");
    double c_minutes3 = minutes_since_creation("Temp3");
    double c_minutes4 = minutes_since_creation("Temp4");
    double c_minutes5 = minutes_since_creation("Temp5");
    double c_minutes6 = minutes_since_creation("Temp6");
    double c_minutes7 = minutes_since_creation("Temp7");
    double c_minutes8 = minutes_since_creation("Temp8");
    double c_minutes9 = minutes_since_creation("Temp9");
    double c_minutes10 = minutes_since_creation("Temp10");
    double c_minutes11 = minutes_since_creation("Temp11");
    double c_minutes12 = minutes_since_creation("Temp12");
    double c_minutes13 = minutes_since_creation("Temp13");
    double c_minutes14 = minutes_since_creation("Temp14");
    double c_minutes15 = minutes_since_creation("Temp15");

    //Get minutes since updated
    double m_minutes1 = minutes_since_last_modified("Temp");
    double m_minutes2 = minutes_since_last_modified("Temp2");
    double m_minutes3 = minutes_since_last_modified("Temp3");
    double m_minutes4 = minutes_since_last_modified("Temp4");
    double m_minutes5 = minutes_since_last_modified("Temp5");
    double m_minutes6 = minutes_since_last_modified("Temp6");
    double m_minutes7 = minutes_since_last_modified("Temp7");
    double m_minutes8 = minutes_since_last_modified("Temp8");
    double m_minutes9 = minutes_since_last_modified("Temp9");
    double m_minutes10 = minutes_since_last_modified("Temp10");
    double m_minutes11 = minutes_since_last_modified("Temp11");
    double m_minutes12 = minutes_since_last_modified("Temp12");
    double m_minutes13 = minutes_since_last_modified("Temp13");
    double m_minutes14 = minutes_since_last_modified("Temp14");
    double m_minutes15 = minutes_since_last_modified("Temp15");

    //Get first 20 characters
    char read1[21];
    read_first_20_characters("temp1", read1, sizeof(read1));
    char read2[21];
    read_first_20_characters("temp2", read2, sizeof(read2));
    char read3[21];
    read_first_20_characters("temp3", read3, sizeof(read3));
    char read4[21];
    read_first_20_characters("temp4", read4, sizeof(read4));
    char read5[21];
    read_first_20_characters("temp5", read5, sizeof(read5));
    char read6[21];
    read_first_20_characters("temp6", read6, sizeof(read6));
    char read7[21];
    read_first_20_characters("temp7", read7, sizeof(read7));
    char read8[21];
    read_first_20_characters("temp8", read8, sizeof(read8));
    char read9[21];
    read_first_20_characters("temp9", read9, sizeof(read9));
    char read10[21];
    read_first_20_characters("temp10", read10, sizeof(read10));
    char read11[21];
    read_first_20_characters("temp11", read11, sizeof(read11));
    char read12[21];
    read_first_20_characters("temp12", read12, sizeof(read12));
    char read13[21];
    read_first_20_characters("temp13", read13, sizeof(read13));
    char read14[21];
    read_first_20_characters("temp14", read14, sizeof(read14));
    char read15[21];
    read_first_20_characters("temp15", read15, sizeof(read15));

    //Maze will be built out here for logical order and simplicity and moved to the main functions
    //Flags. A-J are flags for 1st cycle
    int a = 0; //1
    int b = 0; //2
    int c = 0; //3
    int d = 0; //4
    int e = 0; //5
    int f = 0; //6
    int g = 0; //7
    int h = 0; //8
    int i = 0; //9
    int j = 0; //10

    // Flags k-t are for second cycle
    int k = 0; //1
    int l = 0; //2
    int m = 0; //3
    int n = 0; //4
    int o = 0; //5
    int p = 0; //6
    int q = 0; //7
    int r = 0; //8
    int s = 0; //9
    int t = 0; //10

    //Cycle keys
    int A[10] = {-1,1,-1,1,-1,1,-1,-1,1,1};
    int B[10] = {-1,1,1,1,1,1,-1,-1,1,-1};

    //Cycle 1 Logic Comparisons
    //B1
    if() {
        if(cycle = 1) {
            a = -1; //1
            c = 1; //3
            d = 1; //4
        }
        if(cycle = 2) {
            k = -1; //1
            m = 1; //3
            n = 1; //4
        }
    }
    //B2
    if() {
        if(cycle = 1) {
            a = -1;  //1
            d = 1;  //4
            e = 1;  //5
        }
        if (cycle = 2) {
            k = -1; //1
            n = 1; //4
            o = 1; //5
        }
    }
    //B3
    if() {
        if(cycle = 1) {
            b = 1; //2
            g = 1; //7
            i = 1; //9
        }
        if(cycle = 2) {
            l = 1; //2
            q = 1; //7
            s = 1; //9
        }
    }
    //B4
    if() {
        if(cycle = 1) {
            c = 1; //3
            f = 1; //6
            g = -1; //7
        }
        if(cycle = 2) {
            m = 1; //3
            p = 1; //6
            q = -1; //7
        }
    }
    //B5
    if() {
        if(cycle = 1) {
            b = 1; //2
            i = -1; //9
            j = 1; //10
        }
        if(cycle = 2) {
            l = 1; //2
            s = -1; //9
            t = 1; //10
        }
    }
    //B6
    if() {
        if(cycle = 1) {
            a = 1; //1
            d = 1; //4
            f = -1; //6
        }
        if(cycle = 2) {
            k = 1; //1
            n = 1; //4
            p = -1; //6
        }
    }
    //B7
    if() {
        if(cycle = 1) {
            b = -1; //2
            e = 1; //5
            j = 1; //10
        }
        if(cycle = 2) {
            l = -1; //2
            o = 1; //5
            t = 1; //10
        }
    }
    //B8
    if() {
        if(cycle = 1) {
            a = -1; //1
            c = 1; //3
            d = 1; //4
        }
        if(cycle = 2) {
            k = -1; //1
            m = 1; //3
            n = 1; //4
        }
    }
    //B9
    if () {
        if(cycle = 1) {
            g = 1; //7
            h = 1; //8
            j = -1; //10
        }
        if(cycle = 2) {
            q = 1; //7
            r = 1; //8
            t = -1; //10
        }
    }
    //B10
    if() {
        if(cycle = 1) {
            c = 1; //3
            d = 1; //4
            i = -1; //9
        }
        if (cycle = 2) {
            m = 1; //3
            n = 1; //4
            s = -1; //9
        }
    }
    //B11
    if() {
        if (cycle = 1) {
            c = -1; //3
            d = 1; //4
            i = 1; //9
        }
        if (cycle = 2) {
            m = -1; //3
            n = 4; //4
            s = 1;
        }
    }
    //B12
    if() {
        if (cycle = 1) {
            a = 1; //1
            f = 1; //6
            h = -1; //8
        }
        if (cycle = 2) {
            k = 1; //1
            p = 1; //6
            r = -1; //8
        }
    }
    //B13
    if() {
        if (cycle = 1) {
            h = 1; //8
            i = -1; //9
            j = 1; //10
        }
        if (cycle = 2) {
            r = 1; //8
            s = -1; //9
            t = 1; //10
        }
    }
    //B14
    if() {
        if (cycle = 1) {
            c = 1; //3
            f = -1; //6
            g = 1; //7
        }
        if (cycle = 2) {
            m = 1; // 3
            p = -1; //6
            q = 7; //7
        }
    }
        //B15
        if() {
            if (cycle = 1) {
                f = -1; //6
                i = 1; //9
                j = 1; //10
            }
            if (cycle = 2) {
                p = -1; //6
                s = 1; //9
                t = 1; //10
            }
        }

        //B16
        if() {
            if (cycle = 1) {
                c = -1; //3
                d = 1; //4
                j = 1; //10
            }
            if (cycle = 2) {
                m = -1; //3
                n = 1; //4
                t = 1; //10
            }
        }
        //B17
        if() {
            if (cycle = 1) {
                b = 1; //2
                d = 1; //4
                g = -1; //7
            }
            if (cycle = 2) {
                l = 1; //2
                n = 1; //4
                q = -1; //7
            }
        }
        //B18
        if() {
            if(cycle = 1) {
                a = 1; //1
                c = 1; //3
                i = -1; //9
            }
            if (cycle = 2) {
                k = 1; //1
                m = 1; //3
                s = -1; //9
            }
        }
        //B19
        if() {
            if (cycle = 1) {
                a = 1; //1
                f = 1; //6
                s = -1; //9
            }
            if (cycle = 2) {
                k = 1; //1
                p = 1; //6
                s = -1; //9
            }
        }
        //B20
        if() {
            if (cycle = 1) {
                c = -1; //3
                e = 1; //5
                g = 1; //7
            }
            if (cycle = 2) {
                m = -1; //3
                o = 1; //5
                q = 1; //7
            }
        }
        //B21
        if() {
            if (cycle = 1) {
                b = 1; //2
                d = 1; //4
                j = -1; //10
            }
            if (cycle = 2) {
                l = 1; //2
                n = 1; //4
                t = -1; //10
            }
        }
        //B22
        if() {
            if (cycle = 1) {
                c = 1; //3
                e = 1; //5
                g = -1; //7
            }
            if (cycle = 2) {
                m = 1; //3
                o = 1; //5
                q = -1; //7
            }
        }
        //B23
        if() {
            if (cycle = 1) {
                a = -1; //1
                c = 1; //3
                d = 1; //4
            }
            if (cycle = 2) {
                k = -1; //1
                m = 1; //3
                n = 1; //4
            }
        }
        //B24
        if() {
            if (cycle = 1) {
                b = 1; //2
                e = -1; //5
                i = 1; //9
            }
            if (cycle = 2) {
                l = 2; //2
                o = -1; //5
                s = 1; //9
            }
        }
        //B25
        if() {
            if (cycle = 1) {
                a = 1; //1
                d = 1; //4
                g = -1; //7
            }
            if (cycle = 2) {
                k = 1; //1
                n = 1; //4
                q = -1; //7
            }
        }
        //B26
        if() {
            if (cycle = 1) {
                b = 1; //2
                d = 1; //4
                f = -1; //6
            }
            if (cycle = 2) {
                l = 1; //2
                n = 1; //4
                p = -1; //6
            }

        }
        //B27
        if() {
            if (cycle = 1) {
                a = -1; //1
                c = 1; //3
                f = 1; //6
            }
            if (cycle = 2) {
                k = -1; //1
                m = 1; //3
                p = 1; //6
            }
        }
        //B28
        if() {
            if (cycle = 1) {
                d = 1; //4
                f = -1; //6
                h = 1; //8
            }
            if (cycle = 2) {
                n = 1; //4
                p = -1; //6
                r = 1; //8
            }
        }
        //B29
        if() {
            if (cycle = 1) {
                e = -1; //5
                f = 1; //6
                i = 1; //9
            }
            if (cycle = 2) {
                o = -1; //5
                p = 1; //6
                s = 1; //9
            }
        }
        //B30
        if() {
            if (cycle = 1) {
                b = 1; //2
                c = -1; //3
                j = 1; //10
            }
            if (cycle = 2) {
                l = 1; //2
                m = -1; //3
                t = 1; //10
            }
        }

        //Compare flags a-j to intA[10] and flags k-t to intB[10]
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