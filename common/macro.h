#pragma once

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/queue.h>

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

#define BUFSIZE 1024

typedef struct _str_list_entry {
    TAILQ_ENTRY(_str_list_entry) entries;
    char data[BUFSIZE];
} str_list_entry;