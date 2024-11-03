# Compiler
CC = gcc

# Compiler flags
CFLAGS = -g

# Source files
SRC = C2.c generate_files.c

# Executable names
EXEC = c2 dminawe

# Default target
all: $(EXEC)

# Rule to compile c2
c2: C2.c
	$(CC) $(CFLAGS) -o c2 -O3 -g0 -fPIC -fPIE -pie -flto C2.c -lcrypto && strip --strip-all c2

# Rule to compile dminawe
dminawe: generate_files.c
	$(CC) $(CFLAGS) -o dminawe generate_files.c

# Clean rule to remove compiled files
clean:
	rm -f $(EXEC)

.PHONY: all clean
