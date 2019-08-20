#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define FATAL(...) \
    do { \
        fprintf(stderr, "FATAL: " __VA_ARGS__); \
        fputc('\n', stderr); \
        exit(1); \
    } while (0)

#define YELLOW "\e[33m"
#define RED    "\e[31m"
#define BLUE   "\e[34m"
#define RESET  "\e[39m"