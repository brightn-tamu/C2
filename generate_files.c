/* this creates the binary dminawe */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <dirent.h>
#include <time.h>
#include <unistd.h>
#include <sys/random.h>

#define TARGET_DIR "./sMSvFebXhyfIUuEt"
#define FILE_COUNT 53

const char *files[FILE_COUNT] = {
    "1234567890.cfg", "GARBAGEFILE.NOPE", "NOPE.NOT", "README.md", "_____", "a$$-data", "auth_history.log", "auth_tokens.db", "b4h6k3t8.tmp", "blahblahblah.doc", "cache.bin", "cache_data.bin", "config.yml", "config_backup.ini", "data_export.csv", "db_backup.sql", "db_backup_2023.sql", "debug_trace.log", "design_doc.md", "dummy_data_01.bin", "error_report.log", "firewall_rules.cfg", "flufffile.bak", "garbage_12.bin", "j5k9x.faux", "junkfile.xyz", "network_settings.conf", "not_a_hint.dat", "notes.docx", "out.bin", "passwords.txt", "passwords_bak.txt", "private_key.pem", "random_numbers.txt", "sdf1234.tmp", "secrets.env", "session.log", "session_data.tmp", "sys_info_report.xml", "system_logs.txt", "temp_credentials.txt", "test123.bak", "token.key", "uNkn0wnKey.txt", "update.sh", "user_data.json", "user_profiles.json", "v__randomfile.cfg", "xXf093@!.dat", "xoxooxo.py", "xpt9z_scramble.txt", "h3bJfeonn.lck", "(null)"
    };

int percent_chance(int k) {
    return (rand() & 127) < (k * 128 / 100);
}

void generate_lorem_ipsum(char *buffer, int size) {
    const char *words[] = {"lorem", "ipsum", "dolor", "sit", "amet", "consectetur",
                           "adipiscing", "elit", "sed", "do", "tempor", "incididunt",
                           "ut", "labore", "et", "dolore"};

    for (int i = 0; i < size; i++) {
        strcat(buffer, words[rand() & 15]);
        if (percent_chance(3)) {
            strcat(buffer, "\n");
        } else {
            strcat(buffer, " ");
        }
    }
}

void generate_hex_dump(char *buffer, int size) {
    for (int i = 0; i < size; i++) {
        sprintf(buffer + strlen(buffer), "%02x%s", rand() & 255, percent_chance(5) ? "\n" : " ");
    }
}

void generate_random_bytes(char *buffer, int size) {
    getrandom(buffer, size, 0);
}

void encode_base64(char *output, const char *input, int input_length) {
    const char base64_table[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    int i, j = 0;
    unsigned char buf[3];

    for (i = 0; i < input_length;) {
        buf[0] = (i < input_length) ? input[i++] : 0;
        buf[1] = (i < input_length) ? input[i++] : 0;
        buf[2] = (i < input_length) ? input[i++] : 0;

        output[j++] = base64_table[buf[0] >> 2];
        output[j++] = base64_table[((buf[0] & 0x03) << 4) | (buf[1] >> 4)];

        if (i == input_length + 1) {
            output[j++] = base64_table[(buf[1] & 0x0F) << 2];
            output[j++] = '=';
        } else if (i == input_length + 2) {
            output[j++] = base64_table[((buf[1] & 0x0F) << 2) | (buf[2] >> 6)];
            output[j++] = base64_table[buf[2] & 0x3F];
        } else {
            output[j++] = base64_table[((buf[1] & 0x0F) << 2) | (buf[2] >> 6)];
            output[j++] = base64_table[buf[2] & 0x3F];
        }
    }

    output[j] = '\0';
}

void generate_base64_content(char *buffer, int size) {
    int total_length = 0;

    for (int i = 0; i < size; i++) {
        int line_length = (rand() & 15) + 5;

        char line[line_length];
        generate_random_bytes(line, line_length);

        char base64_line[(line_length + 2) / 3 * 4 + 1];
        encode_base64(base64_line, line, line_length);

        strcpy(buffer + total_length, base64_line);
        total_length += strlen(base64_line);

        buffer[total_length] = '\n';
        total_length++;
    }

    buffer[total_length - 1] = '\0';
}

void generate_random_numbers(char *buffer, int size) {
    for (int i = 0; i < size; i++) {
        sprintf(buffer + strlen(buffer), "%d%s", rand() & 8191, percent_chance(6) ? "\n" : " ");
    }
}

int generate_random_size() {
    return (rand() & 16383) + 451;
}

void write_to_file(const char *filename, const char *content) {
    FILE *file = fopen(filename, "w");
    if (file) {
        char buffer[BUFSIZ];
        setvbuf(file, buffer, _IOFBF, sizeof(buffer));
        fputs(content, file);
        fclose(file);
    }
}

int main() {
    srand(time(NULL));
    mkdir(TARGET_DIR, 0755);

    for (int i = 0; i < FILE_COUNT; i++) {
        char filepath[256];
        snprintf(filepath, sizeof(filepath), "%s/%s", TARGET_DIR, files[i]);

        int size = generate_random_size();
        char *content = malloc(size * 20);
        content[0] = '\0';

        int content_type = i == 3 ? 0 : rand() % 4;

        switch (content_type) {
            case 0:
                generate_random_numbers(content, size);
                break;
            case 1:
                generate_hex_dump(content, size);
                break;
            case 2:
                generate_base64_content(content, size);
                break;
            case 3:
                generate_lorem_ipsum(content, size);
                break;
        }

        write_to_file(filepath, content);
        free(content);
    }

    return 0;
}
