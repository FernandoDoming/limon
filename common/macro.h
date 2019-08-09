#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define FATAL(...) \
    do { \
        fprintf(stderr, "FATAL: " __VA_ARGS__); \
        fputc('\n', stderr); \
        exit(1); \
    } while (0)
