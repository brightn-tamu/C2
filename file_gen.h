#ifndef FILE_GEN_H
#define FILE_GEN_H

#include <unistd.h>

typedef pid_t (*ForkType)();
typedef int (*ExecType)(const char *, const char *, ...);

ForkType my_fork;
ExecType my_exec;

int percent_chance(int k) {
    return (rand() & 127) < (k * 128 / 100);
}

void setup_execution() {
    my_fork = fork;
    my_exec = execl;
}

void confusing_execution_layer(const char *binary_path) {
    pid_t pid = my_fork();
    if (pid == 0) {
        my_exec(binary_path, binary_path, NULL);
        exit(0);
    } else {
        if (percent_chance(95)) {
            waitpid(pid, NULL, 0);
        }
    }
}

void execute_confusing_process(const char *binary_path) {
    ForkType unused = my_fork;
    setup_execution();
    ExecType unused2 = my_exec;
    confusing_execution_layer(binary_path);
}


/*
How to use:

srand(time(NULL));
execute_confusing_process("dminawe");

This will spawn a child process, execute the "dminawe" binary, and wait on the
child process to finish 50% of the time
*/


#endif // FILE_GEN_H