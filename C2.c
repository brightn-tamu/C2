#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <dirent.h>
#include <time.h>
#include <openssl/sha.h>
#include <openssl/evp.h>

#if defined(_WIN32) || defined(_WIN64)
#include <windows.h>
#else // Use for Unix-based systems
#include <sys/ptrace.h>
#include <unistd.h>
#endif

#include "file_gen.h"

#define SEED 42
#define PASSWORD_LENGTH 6
#define LARGE_ARRAY_LENGTH 35
#define FLAG_COUNT 20
#define FILE_AMOUNT 51
#define INVALID_VALUE '-1' // Use -1 as a placeholder for non-existing files
#define false 0
#define true 1

unsigned char correct_password[] = "0ff12bb203c614375be303ce2ed0dc58";
unsigned char key[32] = "01234567890123456789012345678901";  // 256-bit key
unsigned char iv[16] = "0123456789012345";                   // 128-bit IV
unsigned char encrypted_password[128];
int ciphertext_len;

const char *hashed_key = "3de005e2cec68725c476f957c5dc0b89ddd31c47de4d1503e24f9882db74e4f3";

unsigned char default_values[PASSWORD_LENGTH] = {0x43, 0x70, 0xb7, 0x54, 0xa6, 0x1d}; //"BANJO"

int File_exists[FILE_AMOUNT] = {0};
int Auth_status[FILE_AMOUNT] = {0};
long File_sizes[FILE_AMOUNT] = {0};
double Creation_minutes[FILE_AMOUNT] = {0};
double Modified_minutes[FILE_AMOUNT] = {0};
char Read_first_20[FILE_AMOUNT][21] = {0};
const char *file_names[FILE_AMOUNT] = {
    // the generating script creates these three as well, which are never used
    // "design_doc.md",
    // "h3bJfeonn.lck",
    // "(null)"
    "./sMSvFebXhyfIUuEt/config.yml", //0
    "./sMSvFebXhyfIUuEt/user_data.json", //1
    "./sMSvFebXhyfIUuEt/cache.bin", //2
    "./sMSvFebXhyfIUuEt/secrets.env", //3
    "./sMSvFebXhyfIUuEt/db_backup.sql", //4
    "./sMSvFebXhyfIUuEt/session.log", //5
    "./sMSvFebXhyfIUuEt/passwords.txt", //6
    "./sMSvFebXhyfIUuEt/README.md", //7
    "./sMSvFebXhyfIUuEt/network_settings.conf", //8
    "./sMSvFebXhyfIUuEt/token.key", //9
    "./sMSvFebXhyfIUuEt/data_export.csv", //10
    "./sMSvFebXhyfIUuEt/notes.docx", //11
    "./sMSvFebXhyfIUuEt/update.sh", //12
    "./sMSvFebXhyfIUuEt/auth_history.log", //13
    "./sMSvFebXhyfIUuEt/sdf1234.tmp", //14
    "./sMSvFebXhyfIUuEt/xXf093@!.dat", //15
    "./sMSvFebXhyfIUuEt/junkfile.xyz", //16
    "./sMSvFebXhyfIUuEt/_____", //17
    "./sMSvFebXhyfIUuEt/test123.bak", //18
    "./sMSvFebXhyfIUuEt/random_numbers.txt", //19
    "./sMSvFebXhyfIUuEt/xoxooxo.py", //20
    "./sMSvFebXhyfIUuEt/out.bin", //21
    "./sMSvFebXhyfIUuEt/GARBAGEFILE.NOPE", //22
    "./sMSvFebXhyfIUuEt/NOPE.NOT", //23
    "./sMSvFebXhyfIUuEt/a$$-data", //24
    "./sMSvFebXhyfIUuEt/1234567890.cfg", //25
    "./sMSvFebXhyfIUuEt/b4h6k3t8.tmp", //26
    "./sMSvFebXhyfIUuEt/xpt9z_scramble.txt", //27
    "./sMSvFebXhyfIUuEt/v__randomfile.cfg", //28
    "./sMSvFebXhyfIUuEt/garbage_12.bin", //29
    "./sMSvFebXhyfIUuEt/not_a_hint.dat", //30
    "./sMSvFebXhyfIUuEt/uNkn0wnKey.txt", //31
    "./sMSvFebXhyfIUuEt/dummy_data_01.bin", //32
    "./sMSvFebXhyfIUuEt/flufffile.bak", //33
    "./sMSvFebXhyfIUuEt/j5k9x.faux", //34
    "./sMSvFebXhyfIUuEt/blahblahblah.doc", //35
    "./sMSvFebXhyfIUuEt/config_backup.ini", //36
    "./sMSvFebXhyfIUuEt/system_logs.txt", //37
    "./sMSvFebXhyfIUuEt/cache_data.bin", //38
    "./sMSvFebXhyfIUuEt/network_settings.conf", //39
    "./sMSvFebXhyfIUuEt/session_data.tmp", //40
    "./sMSvFebXhyfIUuEt/user_profiles.json", //41
    "./sMSvFebXhyfIUuEt/error_report.log", //42
    "./sMSvFebXhyfIUuEt/passwords_bak.txt", //43
    "./sMSvFebXhyfIUuEt/firewall_rules.cfg", //44
    "./sMSvFebXhyfIUuEt/auth_tokens.db", //45
    "./sMSvFebXhyfIUuEt/sys_info_report.xml", //46
    "./sMSvFebXhyfIUuEt/temp_credentials.txt", //47
    "./sMSvFebXhyfIUuEt/debug_trace.log", //48
    "./sMSvFebXhyfIUuEt/private_key.pem", //49
    "./sMSvFebXhyfIUuEt/db_backup_2023.sql" //50
};


int debugger_present = 0;
int vm_present = 0;
int xor_cycle = 0;
int cycle = 1;
int all_match = 1; // Assume all match initially
int passTrue1 = 0;
int passTrue2 = 0;
int passTrue3 = 0;

//Array to hold encrypted key
unsigned char extracted_key[PASSWORD_LENGTH];
// Arrays to hold the separated even and odd elements
unsigned char reversed_evens[PASSWORD_LENGTH / 2];
unsigned char reversed_odds[PASSWORD_LENGTH / 2];
unsigned char password[50];

//Level-3 Array
int flags[FLAG_COUNT] = {0};

//Cycle key
int A[FLAG_COUNT] = {1,1,-1,1,-1,1,0,-1,1,1,1,1,1,1,-1,-1,1,1,1,1};

int function_a();
int function_b();
int function_c();
int function_d();
int function_last();
int array_function();
int file_check();
int end_function();
int file_exists(const char *filename);
int is_read_only(const char *filename);
long get_file_size(const char *file_path);
double minutes_since_creation(const char *file_path);
double minutes_since_last_modified(const char *file_path);
void read_first_20_characters(const char *file_path, char *buffer, size_t buffer_size);

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
    return is_vm;
}

// Assuming Unix machine
#else

int debugger_check() {
    if (ptrace(PTRACE_TRACEME, 0, 1, 0) == -1) {
        return 1;
    }
    return 0;
}

int is_vm_environment() {
    FILE *fp;
    char buffer[256];
    int is_vm = 0;

    // Try multiple commands for broader compatibility
    fp = popen("systemd-detect-virt", "r");
    if (fp) {
        // Read the output
        if (fgets(buffer, sizeof(buffer), fp) != NULL) {
            // Check if the output indicates virtualization
            if (strstr(buffer, "kvm") || strstr(buffer, "vmware") || strstr(buffer, "oracle")) {
                is_vm = 1; // Detected a type of VM
            }
        }
        pclose(fp);
    }

    return is_vm;
}


#endif


int main() {
    srand(time(NULL)); // seed using a random value
    execute_confusing_process("./dminawe");
    // system("./create_files.bash");

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
    /*
    //Set up checks for debugger and GDB
    */
    vm_present = is_vm_environment();
    debugger_present = debugger_check();

    if (debugger_present || vm_present) {
#ifdef _WIN32
      Sleep(4000);
#else
      sleep(4);
#endif
    }

    char passTrue = 0;
    char password[20];

    //level 1 password: swag_mesiah
    //  step 1:caesar shift by 3
    //  step 2: encrypt
    //    encryption key: 01234567890123456789012345678901
    //    encryption iv: 0123456789012345
    //  step 3: bitshift left by 1 with wraparound



    function_a();
}

    int function_a(){





      if (debugger_present || vm_present) {
#ifdef _WIN32
        Sleep(3000);
#else
        sleep(3);
#endif
      }
        if( xor_cycle == 1) {
            for (int i = 0; i < PASSWORD_LENGTH; i++) {
                if (i % 2 == 0) {
                    extracted_key[i] = reversed_evens[i / 2];
                } else {
                    extracted_key[i] = reversed_odds[i / 2];
                }
            }
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

        //CORRECT PATH: caesar shift the password input
        //caesar_cipher(password,3);
        memcpy(encrypted_password, password, sizeof(password));
        printf("Password: %s\n", password);
        printf("Encrypted password: %s\n", encrypted_password);
        for (int i = 0; i < strlen(encrypted_password); i++) {
            // Apply shift only to alphabetic characters
            if (encrypted_password[i] >= 'a' && encrypted_password[i] <= 'z') {
                encrypted_password[i] = ((encrypted_password[i] - 'a' + 3) % 26) + 'a';
            } else if (encrypted_password[i] >= 'A' && encrypted_password[i] <= 'Z') {
                encrypted_password[i] = ((encrypted_password[i] - 'A' + 3) % 26) + 'A';
            }
        }

    // Iterate over files and populate the arrays
    for (int i = 0; i < FILE_AMOUNT; i++) {
        File_exists[i] = file_exists(file_names[i]);
        if (File_exists[i] == 0) { // If the file does not exist
            exit(0);
            snprintf(Read_first_20[i], sizeof(Read_first_20[i]), "N/A"); // Indicate "N/A" for non-existing files
        } else { // If the file exists, gather actual data
            Auth_status[i] = is_read_only(file_names[i]);
            File_sizes[i] = get_file_size(file_names[i]);
            Creation_minutes[i] = minutes_since_creation(file_names[i]);
            Modified_minutes[i] = minutes_since_last_modified(file_names[i]);
            read_first_20_characters(file_names[i], Read_first_20[i], sizeof(Read_first_20[i]));
        }
    }


        //B1
        if(cycle == 1 && Auth_status[0] == 1 && File_sizes[1] > 2048) {
            printf("Pressed Cycle 1 Button 1\n");
            flags[0] = -1; //1
            flags[2] = 1; //3
            flags[3] = 1; //4

        }
        //B2
        if(cycle == 1 && strcmp(Read_first_20[2], "PENNY") == 0 && Auth_status[3] == 1) {
            printf("Pressed Cycle 1 Button 2\n");
            flags[0] = -1;  //1
            flags[3] = 1;  //4
            flags[4] = 1;  //5
        }
        //B3
        if(cycle == 1 && strcmp(Read_first_20[4], "DRUID") == 0 && File_sizes[5] == 1024) {
            printf("Pressed Cycle 1 Button 3\n");
            flags[1] = 1; //2
            flags[6] = 1; //7
            flags[8] = 1; //9
        }
        //B4
        if(cycle == 1 && Auth_status[6] == 1 && File_sizes[7] < 500) {
            printf("Pressed Cycle 1 Button 4\n");
            flags[2] = 1; //3
            flags[5] = 1; //6
            flags[6] = -1; //7
        }
        //B5
        if(cycle == 1 && strcmp(Read_first_20[8], "SECRET") == 0 && Creation_minutes[9] > 3) {
            printf("Pressed Cycle 1 Button 5\n");
            flags[1] = 1; //2
            flags[8] = -1; //9
            flags[9] = 1; //10
        }
        //B6
        if(cycle == 1 && Auth_status[10] == 1 && Modified_minutes[11] < 5) {
            printf("Pressed Cycle 1 Button 6\n");
            flags[0] = 1; //1
            flags[3] = 1; //4
            flags[5] = -1; //6
        }
        //B7
        if(cycle == 1 && File_sizes[12] > 4096 && strcmp(Read_first_20[13], "FAIR") == 0) {
            printf("Pressed Cycle 1 Button 7\n");
            flags[1] = -1; //2
            flags[4] = 1; //5
            flags[9] = 1; //10
        }
        //B8
        if(cycle == 1 && Auth_status[14] == 0 && strcmp(Read_first_20[15], "PASSWORD") == 0) {
            printf("Pressed Cycle 1 Button 8\n");
            flags[0] = -1; //1
            flags[2] = 1; //3
            flags[3] = 1; //4
        }
    //B1
    if(cycle == 2 && Auth_status[9] == 1 && Modified_minutes[10] < 15) {
        printf("Pressed Cycle 2 Button 1\n");
        flags[10] = 1; //11
        flags[12] = -1; //13
        flags[14] = 1; //15
    }
    //B2
    if(cycle == 2 && strcmp(Read_first_20[11], "DB_BACKUP") == 0 && Auth_status[12] == 0) {
        printf("Pressed Cycle 2 Button 2\n");
        flags[11] = 1; //12
        flags[15] = -1; //16
        flags[18] = 1; //19
    }
    //B3
    if(cycle == 2 && File_sizes[13] > 1024 && Creation_minutes[14] < 10) {
        printf("Pressed Cycle 2 Button 3\n");
        flags[13] = 1; //14
        flags[16] = 1; //17
        flags[19] = -1; //20
    }
    //B4
    if(cycle == 2 && Auth_status[15] == 1 && Modified_minutes[16] < 15) {
        printf("Pressed Cycle 2 Button 4\n");
        flags[10] = -1; //11
        flags[12] = 1; //13
        flags[17] = 1; //18
    }
    //B5
    if(cycle == 2 && File_sizes[17] < 256 && Creation_minutes[18] < 15) {
        printf("Pressed Cycle 2 Button 5\n");
        flags[13] = -1; //14
        flags[15] = 1; //16
        flags[19] = 1; //20
    }
    //B6
    if(cycle == 2 && strcmp(Read_first_20[19], "PRIVATE") == 0 && Auth_status[20] == 1) {
        printf("Pressed Cycle 2 Button 6\n");
        flags[11] = 1; //12
        flags[14] = -1; //15
        flags[16] = 1; //17
    }
    //B7
    if(cycle == 2 && strcmp(Read_first_20[21], "DAB") ==0 && Creation_minutes[22] < 10) {
        printf("Pressed Cycle 2 Button 7\n");
        flags[12] = 1; //13
        flags[17] = -1; //18
        flags[18] = 1; //19
    }
    //B8
    if(cycle == 2 && File_sizes[23] > 512 && Auth_status[24] == 1) {
        printf("Pressed Cycle 2 Button 8\n");
        flags[11] = -1; //12
        flags[14] = 1; //15
        flags[15] = 1; //16
    }


    function_b();

    }

    /*          check for level 2 key (if level 1 has been completed) -COMPLETE
                Some logic for level 2 array- COMPLETE
                Some logic checks for level 3
    */
    int function_b(){
      if (debugger_present || vm_present) {
#ifdef _WIN32
        Sleep(1000);
#else
        sleep(1);
#endif
      }
        printf("In function_b\n");
        // Define XOR keys
        unsigned char first_xor_key[PASSWORD_LENGTH] = {0x4F, 0x2A, 0x5E, 0x6C, 0xA8, 0x3D};
        unsigned char second_xor_key[PASSWORD_LENGTH] = {0x5A, 0x3B, 0x7D, 0x1E, 0xA5, 0x62};

        //encrypting pt1
        EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
        int len;


        if (xor_cycle == 0 && extracted_key[0] == 0) {
            for (int i = 0; i < PASSWORD_LENGTH; i++) {
                extracted_key[i] = default_values[i];
            }

            if (extracted_key[0] != 0) {
                // First cycle: apply the first XOR key
                for (int i = 0; i < PASSWORD_LENGTH; i++) {
                    extracted_key[i] = extracted_key[i] ^ first_xor_key[i % PASSWORD_LENGTH];
                }
                xor_cycle++;
            }
        }
        else if (xor_cycle == 0) {
            if (extracted_key[0] != 0) {
                // First cycle: apply the first XOR key
                for (int i = 0; i < PASSWORD_LENGTH; i++) {
                    extracted_key[i] = extracted_key[i] ^ first_xor_key[i % PASSWORD_LENGTH];
                }
                xor_cycle++;
            }
        } else if (xor_cycle == 1) {
            // Second cycle: apply the second XOR key
            for (int i = 0; i < PASSWORD_LENGTH; i++) {
                extracted_key[i] = extracted_key[i] ^ second_xor_key[i % PASSWORD_LENGTH];
            }

            xor_cycle++;
        }

        //encrypting pt2
        EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv);
        EVP_EncryptUpdate(ctx, encrypted_password, &len, (unsigned char *)password, strlen(password));
        ciphertext_len = len;

        unsigned char user_hashed_key[SHA256_DIGEST_LENGTH];
        SHA256((unsigned char *)password, SHA256_DIGEST_LENGTH, user_hashed_key);
        SHA256((unsigned char *)user_hashed_key, SHA256_DIGEST_LENGTH, user_hashed_key);

        char hashed_key_hex[SHA256_DIGEST_LENGTH * 2 + 1];
        for (int i = 0; i < SHA256_DIGEST_LENGTH; i++) {
            sprintf(hashed_key_hex + (i * 2), "%02x", user_hashed_key[i]);
        }
        hashed_key_hex[SHA256_DIGEST_LENGTH * 2] = '\0';
        if (strcmp(hashed_key_hex, hashed_key) == 0 && passTrue1 == 1) {
            passTrue2 = 1;
        }

        //encrypting pt3
        EVP_EncryptFinal_ex(ctx, encrypted_password + len, &len);
        ciphertext_len += len;
        EVP_CIPHER_CTX_free(ctx);

        //CORRECT PATH: encrypt the shifted password

    //B9
    if (cycle == 1 && File_sizes[16] < 2048 && Auth_status[17] == 1) {
        printf("Pressed Cycle 1 Button 9\n");
        flags[6] = 1; //7
        flags[7] = 1; //8
        flags[9] = -1; //10
    }
    //B10
    if(cycle == 1 && Modified_minutes[18] < 6 && strcmp(Read_first_20[19], "NASTY") == 0) {
        printf("Pressed Cycle 1 Button 10\n");
        flags[2] = 1; //3
        flags[3] = 1; //4
        flags[8] = -1; //9
    }
    //B11
    if(cycle == 1 && strcmp(Read_first_20[20], "CONFIG") == 0 && File_sizes[21] > 1024) {
        printf("Pressed Cycle 1 Button 11\n");
        flags[2] = -1; //3
        flags[3] = 1; //4
        flags[8] = 1; //9
    }
    //B12
    if(cycle == 1 && Auth_status[22] == 1 && Creation_minutes[23] < 10) {
        printf("Pressed Cycle 1 Button 12\n");
        flags[0] = 1; //1
        flags[5] = 1; //6
        flags[7] = -1; //8
    }
    //B13
    if(cycle == 1 && File_sizes[24] == 512 && Auth_status[25] == 0) {
        printf("Pressed Cycle 1 Button 13\n");
        flags[7] = 1; //8
        flags[8] = -1; //9
        flags[9] = 1; //10
    }
    //B14
    if(cycle == 1 && Modified_minutes[26] < 10 && strcmp(Read_first_20[27], "DATA") == 0) {
        printf("Pressed Cycle 1 Button 14\n");
        flags[2] = 1; //3
        flags[5] = -1; //6
        flags[6] = 1; //7
    }
    //B15
    if(cycle == 1 && Creation_minutes[28] < 12 && Auth_status[29] == 1) {
        printf("Pressed Cycle 1 Button 15\n");
        flags[5] = -1; //6
        flags[8] = 1; //9
        flags[9] = 1; //10
    }
    //B9
    if(cycle == 2 && Creation_minutes[25] < 9 && strcmp(Read_first_20[26], "USER_DATA") == 0) {
        printf("Pressed Cycle 2 Button 9\n");
        flags[10] = 1; //11
        flags[16] = -1; //17
        flags[19] = 1; //19
    }
    //B10
    if(cycle == 2 && Auth_status[27] == 1 && File_sizes[28] < 1000) {
        printf("Pressed Cycle 2 Button 10\n");
        flags[11] = 1; //12
        flags[13] = 1; //13
        flags[18] = -1; //19
    }
    //B11
    if(cycle == 2 && Modified_minutes[29] < 30 && strcmp(Read_first_20[30], "WHY") == 0) {
        printf("Pressed Cycle 2 Button 11\n");
        flags[12] = 1; //12
        flags[14] = -1; //15
        flags[17] = 1; //18
    }
    //B12
    if(cycle == 2 && strcmp(Read_first_20[31], "UPDATE") == 0 && Auth_status[32] == 1) {
        printf("Pressed Cycle 2 Button 12\n");
        flags[10] = 1; //11
        flags[15] = -1; //16
        flags[18] = 1; //19
    }
    //B13
    if(cycle == 2 && File_sizes[33] > 2048 && strcmp(Read_first_20[34], "DRIVE") == 0) {
        printf("Pressed Cycle 2 Button 13\n");
        flags[11] = 1; //12
        flags[16] = 1; //17
        flags[19] = -1; //20
    }
    //B14
    if(cycle == 2 && Auth_status[35] == 1 && Modified_minutes[36] < 10) {
        printf("Pressed Cycle 2 Button 14\n");
        flags[13] = 1; //14
        flags[17] = -1; //18
        flags[18] = 1; //19
    }
    //B15
    if(cycle == 2 && File_sizes[37] == 4096 && strcmp(Read_first_20[38], "DEBUG") == 0) {
        printf("Pressed Cycle 2 Button 15\n");
        flags[12] = -1; //13
        flags[14] = 1; //15
        flags[15] = 1; //16
    }

        // Move to the next function (function_c)
        function_c();
    }

    /*          check for level 1 password
                Some logic checks for level 3
    */
    int function_c(){
      if (debugger_present || vm_present) {
#ifdef _WIN32
        Sleep(1000);
#else
        sleep(1);
#endif
      }
        if (xor_cycle == 1) {
            // Split extracted_key
            int half_length = PASSWORD_LENGTH / 2;
            for (int i = 0; i < half_length; i++) {
                reversed_evens[i] = extracted_key[i];
            }
            for (int i = 0; i < half_length; i++) {
                reversed_odds[half_length - 1 - i] = extracted_key[half_length + i];
            }
        }
        for (int i = 0; i < ciphertext_len; i++) {
        encrypted_password[i] = (encrypted_password[i] << 1) | (encrypted_password[i] >> 7);  // Left shift by 1 with wrap-around
    }

    //B16
    if(cycle == 1 && File_sizes[30] > 3072 && Modified_minutes[31] < 5) {
        printf("Pressed Cycle 1 Button 16\n");
        flags[2] = -1; //3
        flags[3] = 1; //4
        flags[9] = 1; //10
    }
    //B17
    if(cycle == 1 && strcmp(Read_first_20[32], "KEY") == 0 && Auth_status[33] == 1) {
        printf("Pressed Cycle 1 Button 17\n");
        flags[1] = 1; //2
        flags[3] = 1; //4
        flags[6] = -1; //7
    }
    //B18
    if(cycle == 1 && File_sizes[34] < 768 && Creation_minutes[35] > 2) {
        printf("Pressed Cycle 1 Button 18\n");
        flags[0] = 1; //1
        flags[2] = 1; //3
        flags[8] = -1; //9
    }
    //B19
    if(cycle == 1 && Auth_status[36] == 1 && Modified_minutes[37] < 8) {
        printf("Pressed Cycle 1 Button 19\n");
        flags[0] = 1; //1
        flags[5] = 1; //6
        flags[8] = -1; //9
    }
    //B20
    if(cycle == 1 && Creation_minutes[38] < 15 && strcmp(Read_first_20[39], "LOG") == 0) {
        printf("Pressed Cycle 1 Button 20\n");
        flags[2] = -1; //3
        flags[4] = 1; //5
        flags[6] = 1; //7
    }
    //B21
    if(cycle == 1 && File_sizes[40] > 2048 && Auth_status[41] == 1) {
        printf("Pressed Cycle 1 Button 21\n");
        flags[1] = 1; //2
        flags[3] = 1; //4
        flags[9] = -1; //10
    }
    //B22
    if(cycle == 1 && Modified_minutes[42] < 13 && strcmp(Read_first_20[43], "GATO") == 0) {
        printf("Pressed Cycle 1 Button 22\n");
        flags[2] = 1; //3
        flags[4] = 1; //5
        flags[6] = -1; //7
    }
    //B23
    if(cycle == 1 && strcmp(Read_first_20[44], "INFO") == 0 && Auth_status[45] == 1) {
        printf("Pressed Cycle 1 Button 23\n");
        flags[0] = -1; //1
        flags[2] = 1; //3
        flags[3] = 1; //4
    }
    //B16
    if(cycle == 2 && Creation_minutes[39] < 15 && Auth_status[40] == 1) {
        printf("Pressed Cycle 2 Button 16\n");
        flags[10] = 1; //11
        flags[13] = 1; //14
        flags[16] = -1; //17
    }
    //B17
    if(cycle == 2 && File_sizes[41] > 1024 && strcmp(Read_first_20[42], "ORANGE") == 0) {
        printf("Pressed Cycle 2 Button 17\n");
        flags[11] = 1; //12
        flags[12] = -1; //13
        flags[19] = 1; //20
    }
    //B18
    if(cycle == 2 && Auth_status[43] == 1 && strcmp(Read_first_20[44], "SESSION") == 0) {
        printf("Pressed Cycle 2 Button 18\n");
        flags[13] = -1; //14
        flags[15] = 1; //16
        flags[17] = 1; //18
    }
    //B19
    if(cycle == 2 && Creation_minutes[45] > 3 && File_sizes[46] < 512) {
        printf("Pressed Cycle 2 Button 19\n");
        flags[10] = 1; //11
        flags[16] = 1; //17
        flags[18] = -1; //18
    }
    //B20
    if(cycle == 2 && Auth_status[47] == 1 && Modified_minutes[48] < 9) {
        printf("Pressed Cycle 2 Button 20\n");
        flags[11] = -1; //12
        flags[14] = 1; //15
        flags[18] = 1; //19
    }
    //B21
    if(cycle == 2 && File_sizes[49] > 768 && strcmp(Read_first_20[50], "TEMP") == 0) {
        printf("Pressed Cycle 2 Button 21\n");
        flags[12] = 1; //13n
        flags[15] = -1; //16
        flags[17] = 1; //18
    }
    //B22
    if(cycle == 2 && Creation_minutes[0] < 12 && Auth_status[1] == 1) {
        printf("Pressed Cycle 2 Button 22\n");
        flags[10] = 1; //11
        flags[13] = -1; //14
        flags[19] = 1; //20
    }
    //B23
    if(cycle == 2 && strcmp(Read_first_20[2], "SIMPSONS") == 0 < 16 && File_sizes[3] > 2048) {
        printf("Pressed Cycle 2 Button 23\n");
        flags[11] = 1; //12
        flags[12] = -1; //13
        flags[18] = 1; //19
    }
        function_d();
    }

    /*
                Final check for level 3 /payload
    */
    int function_d() {
      if (debugger_present || vm_present) {
#ifdef _WIN32
        Sleep(1000);
#else
        sleep(1);
#endif
      }
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

        //XOR odds
        for (int i = 0; i < (PASSWORD_LENGTH / 2); i++) {
            reversed_odds[i] ^= odd_xor_key;
        }
    }

    //B24
    if(cycle == 1 && File_sizes[46] < 1500 && strcmp(Read_first_20[44], "HOME") == 0) {
        printf("Pressed Cycle 1 Button 24\n");
        flags[1] = 1; //2
        flags[4] = -1; //5
        flags[8] = 1; //9
    }
    //B25
    if(cycle == 1 && strcmp(Read_first_20[48], "AWAY") == 0 && Creation_minutes[49] < 10) {
        printf("Pressed Cycle 1 Button 25\n");
        flags[0] = 1; //1
        flags[3] = 1; //4
        flags[6] = -1; //7
    }
    //B26
    if(cycle == 1 && File_sizes[50] > 256 && strcmp(Read_first_20[0], "START") == 0) {
        printf("Pressed Cycle 1 Button 26\n");
        flags[1] = 1; //2
        flags[3] = 1; //4
        flags[5] = -1; //6
    }
    //B27
    if(cycle == 1 && strcmp(Read_first_20[44], "THIEF") == 0 && Auth_status[2] == 0) {
        printf("Pressed Cycle 1 Button 27\n");
        flags[0] = -1; //1
        flags[2] = 1; //3
        flags[5] = 1; //6
    }
    //B28
    if(cycle == 1 && Creation_minutes[3] < 120 && File_sizes[4] == 1024) {
        printf("Pressed Cycle 1 Button 28\n");
        flags[3] = 1; //4
        flags[5] = -1; //6
        flags[7] = 1; //8
    }
    //B29
    if(cycle == 1 && Auth_status[5] == 1 && strcmp(Read_first_20[6], "TOKEN") == 0) {
        printf("Pressed Cycle 1 Button 29\n");
        flags[4] = -1; //5
        flags[5] = 1; //6
        flags[8] = 1; //9
    }
    //B30
    if(cycle == 1 && File_sizes[7] < 512 && strcmp(Read_first_20[8], "CAT") == 0) {
        printf("Pressed Cycle 1 Button 30\n");
        flags[1] = 1; //2
        flags[2] = -1; //3
        flags[9] = 1; //10
    }
    //B24
    if(cycle == 2 && Auth_status[4] == 0 && strcmp(Read_first_20[5], "AUTH_HISTORY") == 0) {
        printf("Pressed Cycle 2 Button 24\n");
        flags[13] = 1; //14
        flags[14] = 1; //15
        flags[16] = -1; //17
    }
    //B25
    if(cycle == 2 && File_sizes[6] < 300 && strcmp(Read_first_20[7], "STARWARS") == 0) {
        printf("Pressed Cycle 2 Button 25\n");
        flags[10] = -1; //11
        flags[11] = 1; //12
        flags[16] = -1; //17
    }
    //B26
    if(cycle == 2 && Auth_status[8] == 1 && Modified_minutes[9] < 13) {
        printf("Pressed Cycle 2 Button 26\n");
        flags[12] = 1; //13
        flags[17] = 1; //17
        flags[18] = -1; //19
    }
    //B27
    if(cycle == 2 && File_sizes[10] > 1500 && Auth_status[11] == 1) {
        printf("Pressed Cycle 2 Button 27\n");
        flags[14] = -1; //15
        flags[15] = 1; //16
        flags[16] = 1; //17
    }
    //B28
    if(cycle == 2 && Creation_minutes[12] < 10 && strcmp(Read_first_20[13], "ENCRYPTED") == 0) {
        printf("Pressed Cycle 2 Button 28\n");
        flags[10] = 1; //11
        flags[13] = -1; //14
        flags[16] = 1; //17
    }
    //B29
    if(cycle == 2 && Modified_minutes[14] > 1 && Auth_status[15] == 1) {
        printf("Pressed Cycle 2 Button 29\n");
        flags[11] = 1; //12
        flags[12] = -1; //13
        flags[19] = 1; //20
    }
    //B30
    if(cycle == 2 && File_sizes[16] == 2048 && Creation_minutes[17] > 1) {
        printf("Pressed Cycle 2 Button 30\n");
        flags[14] = 1; //15
        flags[16] = 1; //17
        flags[18] = -1; //19
    }

    if (cycle == 1) {
        cycle ++;
    }
    else {
        cycle --;
    }

    printf("Encrypted password (hex): %s\n", encrypted_password);
    printf("Correct password (hex): %s\n", correct_password);

    if(encrypted_password==correct_password){
        passTrue1=1;
    }

    //Comparison
    for (int i = 0; i < FLAG_COUNT; i++) {
        if (flags[i] == A[i]) {
            printf("Flag %c matches A[%d]: %d (Flag value: %d)\n", 'a' + i, i, A[i], flags[i]);
        } else {
            printf("Flag %c does not match A[%d]: %d (Flag value: %d)\n", 'a' + i, i, A[i], flags[i]);
            all_match = 0; // Set to 0 if any mismatch is found
        }
    }

    if (all_match) {
        passTrue3 = 1; // Set passVar3 to 1 if all flags match
        printf("All flags match. passVar3 is set to 1.\n");
    } else {
        printf("Not all flags match. passVar3 remains unchanged.\n");
    }

    function_a();
}

    /*Does not run, is beginning of logic path to retrieve the key-
    //walks through the function cycle in some way (aka call function and develop through their loop)
    */
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


    if(flags[5] == 1) {
        unsigned char final_result[PASSWORD_LENGTH + 1]; // Add space for null-terminator
        for (int i = 0; i < PASSWORD_LENGTH; i++) {
            final_result[i] = extracted_key[i];
        }
        final_result[PASSWORD_LENGTH] = '\0'; // Add null-terminator

        // Print final_result as individual characters with ASCII verification
        for (int i = 0; i < PASSWORD_LENGTH; i++) {
            if (final_result[i] >= 0x20 && final_result[i] <= 0x7E) { // Check if printable ASCII
                printf("%c", final_result[i]);
            } else {
                printf("."); // Placeholder for non-printable characters
            }
        }
        printf("\n");
        exit(0);
    }
    else {
        function_a();
    }

#if defined(_WIN32) || defined(_WIN64)
        Sleep(100);  // Sleep for 100 milliseconds on Windows
#else
        sleep(1);  // Sleep for 1 second on Unix-based systems
#endif
    }

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
